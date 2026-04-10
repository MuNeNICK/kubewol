// Package agent runs on every node inside the kubewol DaemonSet. It owns
// the BPF programs and maps, dynamically attaches TC to new interfaces, and
// surfaces a gRPC API (defined in proto/kubewol/v1/agent.proto) that the
// unprivileged controller uses to push desired state and subscribe to SYN
// events for direct-scale decisions.
package agent

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/go-logr/logr"

	bpf "github.com/munenick/kubewol/internal/ebpf"
	"github.com/munenick/kubewol/internal/metrics"
)

// AgentAudience is the audience the controller's projected SA token must
// carry to pass the gRPC authentication interceptor. A bearer token whose
// aud claim does not include this value is rejected by the auth interceptor
// in grpc.go regardless of who signed it. Kept in sync with the projected
// volume definition in the controller Deployment manifest.
const AgentAudience = "kubewol.io/agent-api"

// WatchEntrySpec is the protocol-independent description of one Service
// port the agent tracks. grpc.go translates pb.WatchEntry to this shape
// before calling ApplyWatches so the BPF-facing logic has no direct
// dependency on the generated protobuf types.
type WatchEntrySpec struct {
	Namespace   string
	Service     string
	TargetKind  string
	TargetName  string
	ClusterIP   string
	Port        uint16
	NodePort    int32
	ProxyMode   bool
	RstSuppress bool
	DirectScale bool
}

// SynEvent is the payload the ring buffer reader emits to subscribers after
// resolving a BPF ring buffer entry to a logical target workload.
type SynEvent struct {
	Namespace  string
	TargetKind string
	TargetName string
}

// Agent owns the BPF state and is called by the gRPC service layer in grpc.go.
type Agent struct {
	bpf    *bpf.Manager
	logger logr.Logger

	mu sync.Mutex
	// entries is the last applied watch state, keyed by "namespace/service/port".
	entries map[string]*entryState
	// bpfKeyIndex maps from a BPF SvcKey back to the WatchEntrySpec so the
	// ring-buffer reader can resolve SYN events to target workloads.
	bpfKeyIndex map[bpf.SvcKey]*WatchEntrySpec
	// nodePortIndex maps from a network-byte-order NodePort (padded to u32)
	// back to the WatchEntrySpec for NodePort traffic.
	nodePortIndex map[uint32]*WatchEntrySpec

	// subMu protects subs.
	subMu sync.Mutex
	// subs is the set of live SSE-style subscribers — typically a single
	// gRPC stream from the controller, but N when the controller restarts
	// and reconnects before the old one tears down.
	subs map[chan SynEvent]struct{}
}

type entryState struct {
	entry WatchEntrySpec
	key   bpf.SvcKey
	ip    net.IP
}

// New constructs an Agent that wraps an already-initialised BPF Manager.
func New(bpfMgr *bpf.Manager, logger logr.Logger) *Agent {
	return &Agent{
		bpf:           bpfMgr,
		logger:        logger,
		entries:       map[string]*entryState{},
		bpfKeyIndex:   map[bpf.SvcKey]*WatchEntrySpec{},
		nodePortIndex: map[uint32]*WatchEntrySpec{},
		subs:          map[chan SynEvent]struct{}{},
	}
}

func entryKey(e *WatchEntrySpec) string {
	return fmt.Sprintf("%s/%s/%d", e.Namespace, e.Service, e.Port)
}

// ApplyWatches diffs the incoming set against the current state and installs
// the difference into BPF. The lock is held for the whole call so concurrent
// gRPC PutWatches requests serialise cleanly.
func (a *Agent) ApplyWatches(specs []WatchEntrySpec) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	want := make(map[string]*entryState, len(specs))
	for i := range specs {
		e := specs[i]
		ip := net.ParseIP(e.ClusterIP)
		if ip == nil || ip.To4() == nil {
			a.logger.V(1).Info("skip non-IPv4 entry",
				"service", e.Namespace+"/"+e.Service, "ip", e.ClusterIP)
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
		entry := st.entry // copy so the index holds a stable pointer
		a.bpfKeyIndex[st.key] = &entry
		if st.entry.NodePort > 0 {
			npKey := uint32(bpf.Htons(uint16(st.entry.NodePort)))
			a.nodePortIndex[npKey] = &entry
		}
	}
	a.logger.V(1).Info("watches applied", "count", len(a.entries))
	return nil
}

// lookupByBPFKey is invoked from the ring buffer reader to translate a BPF
// event into a logical target workload. Returns nil if the SYN hit a service
// that does not want direct-scale.
func (a *Agent) lookupByBPFKey(dstAddr uint32, dstPort uint16) *WatchEntrySpec {
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

// ServiceMetrics returns per-Service cumulative SYN count aggregated from the
// BPF syn_count map. Consumed by the /metrics exporter (still served over
// HTTPS by controller-runtime's metrics server in agent mode).
func (a *Agent) ServiceMetrics() []metrics.ServiceMetric {
	a.mu.Lock()
	defer a.mu.Unlock()
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

// DropCounts proxies to the BPF Manager. Exposed for the metrics exporter.
func (a *Agent) DropCounts() (map[string]uint64, error) {
	return a.bpf.DropCounts()
}

// subscribe registers a new SynEvent channel. Used by grpc.go to back a
// server-side stream. The returned channel is closed when unsubscribe is
// called; no messages are dropped silently — Agent.emit instead drops to
// per-subscriber on overflow so a slow consumer cannot stall the ring
// buffer reader.
func (a *Agent) subscribe() chan SynEvent {
	ch := make(chan SynEvent, 64)
	a.subMu.Lock()
	a.subs[ch] = struct{}{}
	a.subMu.Unlock()
	return ch
}

func (a *Agent) unsubscribe(ch chan SynEvent) {
	a.subMu.Lock()
	delete(a.subs, ch)
	a.subMu.Unlock()
	close(ch)
}

// emit pushes one event to every live subscriber, dropping for subscribers
// whose queue is full instead of blocking the ringbuf reader.
func (a *Agent) emit(evt SynEvent) {
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
// logical target via lookupByBPFKey, and emits a SynEvent for any match
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
			a.emit(SynEvent{
				Namespace:  entry.Namespace,
				TargetKind: entry.TargetKind,
				TargetName: entry.TargetName,
			})
		}
	}
}

// SynEventReader is the contract the cmd-side ring buffer reader satisfies.
// Kept as an interface so this package does not depend on cilium/ebpf.
type SynEventReader interface {
	ReadEvent() (bpf.SynEvent, error)
	Close() error
}
