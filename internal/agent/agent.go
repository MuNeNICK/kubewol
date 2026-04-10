// Package agent runs on every node inside the kubewol DaemonSet. It owns
// the BPF programs and maps, dynamically attaches TC to new interfaces,
// receives the desired state from the controller via HTTP, and streams
// SYN events back so the unprivileged controller can make direct-scale
// decisions without touching any kernel facilities.
package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/go-logr/logr"

	"github.com/munenick/kubewol/internal/agentapi"
	bpf "github.com/munenick/kubewol/internal/ebpf"
	"github.com/munenick/kubewol/internal/metrics"
)

// AgentAudience is the audience the controller's projected SA token must
// carry to pass the /v1/* audience check. A bearer token whose aud claim
// does not include this value is rejected by the custom metrics filter
// even if it is otherwise valid. Kept in sync with the projected volume
// definition in the controller Deployment manifest.
const AgentAudience = "kubewol.io/agent-api"

// Agent owns the BPF state and the HTTP handlers the controller calls.
type Agent struct {
	bpf    *bpf.Manager
	logger logr.Logger

	mu sync.Mutex
	// entries is the last applied watch state, keyed by "namespace/service/port".
	// The agent replaces this wholesale on every PUT /v1/watches so stale ports
	// are torn down without the controller having to send diffs.
	entries map[string]*entryState
	// bpfKeyIndex maps from a BPF SvcKey back to the logical WatchEntry so the
	// ring-buffer reader can resolve SYN events to target workloads.
	bpfKeyIndex map[bpf.SvcKey]*agentapi.WatchEntry
	// nodePortIndex maps from a network-byte-order NodePort (padded to u32)
	// back to the logical WatchEntry for NodePort traffic.
	nodePortIndex map[uint32]*agentapi.WatchEntry

	// subMu protects subs.
	subMu sync.Mutex
	// subs is the set of live SSE subscribers — typically a single connection
	// from the controller, but N when the controller restarts and reconnects
	// before the old one is torn down.
	subs map[chan agentapi.SynEventMsg]struct{}
}

type entryState struct {
	entry agentapi.WatchEntry
	key   bpf.SvcKey
	ip    net.IP
}

// New constructs an Agent that wraps an already-initialised BPF Manager.
func New(bpfMgr *bpf.Manager, logger logr.Logger) *Agent {
	return &Agent{
		bpf:           bpfMgr,
		logger:        logger,
		entries:       map[string]*entryState{},
		bpfKeyIndex:   map[bpf.SvcKey]*agentapi.WatchEntry{},
		nodePortIndex: map[uint32]*agentapi.WatchEntry{},
		subs:          map[chan agentapi.SynEventMsg]struct{}{},
	}
}

// RegisterHandlers installs the agent HTTP routes onto the given mux.
//
// Authentication and authorization for every request routed here is enforced
// upstream by the custom metrics filter in agent/filter.go: it calls
// TokenReview with an explicit target audience list that includes
// AgentAudience, so any bearer token whose aud claim does not include
// kubewol.io/agent-api is rejected before the handlers ever run. No further
// audience check is needed at this layer.
func (a *Agent) RegisterHandlers(mux *http.ServeMux) {
	mux.HandleFunc(agentapi.PathWatches, a.handleWatches)
	mux.HandleFunc(agentapi.PathSynEvents, a.handleSynEvents)
}

// handleWatches accepts the full desired watch state from the controller and
// rewrites the local BPF maps to match. Missing entries are removed; present
// entries are (re)applied. BPF writes that fail surface as 500s so the
// controller can retry on its next reconcile.
func (a *Agent) handleWatches(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var spec agentapi.WatchSpec
	if err := json.NewDecoder(r.Body).Decode(&spec); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}

	if err := a.applySpec(spec); err != nil {
		a.logger.Error(err, "applySpec failed")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func entryKey(e *agentapi.WatchEntry) string {
	return fmt.Sprintf("%s/%s/%d", e.Namespace, e.Service, e.Port)
}

// applySpec diffs the incoming spec against the current state and installs
// the difference into BPF. Lock is held for the whole call so concurrent
// PUTs serialize cleanly.
func (a *Agent) applySpec(spec agentapi.WatchSpec) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	want := make(map[string]*entryState, len(spec.Watches))
	for i := range spec.Watches {
		e := spec.Watches[i]
		ip := net.ParseIP(e.ClusterIP)
		if ip == nil || ip.To4() == nil {
			a.logger.V(1).Info("skip non-IPv4 entry", "service", e.Namespace+"/"+e.Service, "ip", e.ClusterIP)
			continue
		}
		bpfKey := bpf.SvcKey{Addr: bpf.IPToUint32Must(ip), Port: bpf.Htons(e.Port)}
		want[entryKey(&e)] = &entryState{entry: e, key: bpfKey, ip: ip}
	}

	// Remove entries that are no longer desired.
	for k, st := range a.entries {
		if _, ok := want[k]; ok {
			continue
		}
		if err := a.bpf.RemoveWatch(st.ip, st.entry.Port, st.entry.NodePort); err != nil {
			return fmt.Errorf("RemoveWatch %s: %w", k, err)
		}
		delete(a.bpfKeyIndex, st.key)
		if st.entry.NodePort > 0 {
			npKey := uint32(bpf.Htons(uint16(st.entry.NodePort)))
			delete(a.nodePortIndex, npKey)
		}
		delete(a.entries, k)
	}

	// Install / update the desired entries.
	for k, st := range want {
		if _, err := a.bpf.AddWatch(st.ip, st.entry.Port, st.entry.NodePort); err != nil {
			return fmt.Errorf("AddWatch %s: %w", k, err)
		}
		if err := a.bpf.SetProxyMode(st.key, st.entry.ProxyMode, st.entry.NodePort); err != nil {
			return fmt.Errorf("SetProxyMode %s: %w", k, err)
		}
		if err := a.bpf.SetRstSuppress(st.key, st.entry.RstSuppress, st.entry.NodePort); err != nil {
			return fmt.Errorf("SetRstSuppress %s: %w", k, err)
		}
		a.entries[k] = st
		entry := st.entry // copy to get a stable pointer
		a.bpfKeyIndex[st.key] = &entry
		if st.entry.NodePort > 0 {
			npKey := uint32(bpf.Htons(uint16(st.entry.NodePort)))
			a.nodePortIndex[npKey] = &entry
		}
	}
	a.logger.V(1).Info("watches applied", "count", len(a.entries))
	return nil
}

// lookupByBPFKey is invoked from the ring buffer reader to translate a SYN
// event into a logical target workload. Returns nil if the SYN hit a service
// that does not want direct-scale.
func (a *Agent) lookupByBPFKey(dstAddr uint32, dstPort uint16) *agentapi.WatchEntry {
	a.mu.Lock()
	defer a.mu.Unlock()

	if e, ok := a.bpfKeyIndex[bpf.SvcKey{Addr: dstAddr, Port: dstPort}]; ok {
		if !e.DirectScale {
			return nil
		}
		cp := *e
		return &cp
	}
	if e, ok := a.nodePortIndex[uint32(dstPort)]; ok {
		if !e.DirectScale {
			return nil
		}
		cp := *e
		return &cp
	}
	return nil
}

// ServiceMetrics returns the per-Service cumulative SYN count aggregated from
// the BPF syn_count map. Used by the agent's /metrics exporter.
func (a *Agent) ServiceMetrics() []metrics.ServiceMetric {
	a.mu.Lock()
	defer a.mu.Unlock()
	// Sum counts per Service (entries are per-port).
	type agg struct {
		ns, svc string
		total   uint64
	}
	byKey := map[string]*agg{}
	for _, st := range a.entries {
		count, err := a.bpf.ReadSynCount(st.key)
		if err != nil {
			continue
		}
		k := st.entry.Namespace + "/" + st.entry.Service
		if _, ok := byKey[k]; !ok {
			byKey[k] = &agg{ns: st.entry.Namespace, svc: st.entry.Service}
		}
		byKey[k].total += count
	}
	out := make([]metrics.ServiceMetric, 0, len(byKey))
	for _, v := range byKey {
		out = append(out, metrics.ServiceMetric{Namespace: v.ns, Service: v.svc, Count: v.total})
	}
	return out
}

// DropCounts proxies to the BPF Manager.
func (a *Agent) DropCounts() (map[string]uint64, error) {
	return a.bpf.DropCounts()
}

// handleSynEvents opens a Server-Sent Events stream and forwards every
// direct-scale-eligible SYN event for as long as the client stays connected.
func (a *Agent) handleSynEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	ch := make(chan agentapi.SynEventMsg, 64)
	a.subMu.Lock()
	a.subs[ch] = struct{}{}
	a.subMu.Unlock()
	defer func() {
		a.subMu.Lock()
		delete(a.subs, ch)
		a.subMu.Unlock()
		close(ch)
	}()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	ctx := r.Context()
	keepalive := time.NewTicker(20 * time.Second)
	defer keepalive.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-keepalive.C:
			// SSE comment line; keeps idle proxies from closing the connection.
			_, _ = w.Write([]byte(":ka\n\n"))
			flusher.Flush()
		case evt := <-ch:
			buf, err := json.Marshal(evt)
			if err != nil {
				continue
			}
			_, _ = w.Write([]byte("data: "))
			_, _ = w.Write(buf)
			_, _ = w.Write([]byte("\n\n"))
			flusher.Flush()
		}
	}
}

// emit pushes one event to every live subscriber, dropping for subscribers
// whose queue is full instead of blocking the ringbuf reader.
func (a *Agent) emit(evt agentapi.SynEventMsg) {
	a.subMu.Lock()
	defer a.subMu.Unlock()
	for ch := range a.subs {
		select {
		case ch <- evt:
		default:
			a.logger.V(1).Info("dropping SYN event; subscriber backlog full")
		}
	}
}

// RunRingBufReader consumes the BPF ring buffer, resolves each SYN to a
// logical target via lookupByBPFKey, and emits an SSE event for any match
// that opted into direct-scale.
func (a *Agent) RunRingBufReader(ctx context.Context, reader SynEventReader) {
	defer reader.Close()
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		evt, err := reader.ReadEvent()
		if err != nil {
			return
		}
		if entry := a.lookupByBPFKey(evt.DstAddr, evt.DstPort); entry != nil {
			a.emit(agentapi.SynEventMsg{
				Namespace:  entry.Namespace,
				TargetKind: entry.TargetKind,
				TargetName: entry.TargetName,
			})
		}
	}
}

// SynEventReader is the contract satisfied by cmd-side ring buffer readers.
// Kept as an interface so this package doesn't grow a direct cilium/ebpf dep.
type SynEventReader interface {
	ReadEvent() (bpf.SynEvent, error)
	Close() error
}
