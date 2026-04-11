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
	// orphans holds BPF state that we failed to tear down during a
	// previous ApplyWatches call. Each entry here is a best-effort
	// retry target: at the top of every ApplyWatches we try to
	// RemoveWatch each orphan again, and drop it from the list on
	// success. Without this list a RemoveWatch error would silently
	// leak the underlying watch_svc / proxy_mode / rst_suppress / etc.
	// entries because a.entries no longer references the stale key.
	orphans []*entryState

	// subMu protects subs.
	subMu sync.Mutex
	// subs is the set of live SubscribeSynEvents gRPC stream subscribers —
	// typically a single stream from the controller, but N when the
	// controller restarts and reconnects before the old one tears down.
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

// installEntryLocked programs a single entryState into BPF. On any partial
// failure it rolls back the steps it already took. If the rollback's
// RemoveWatch itself fails the half-installed state is queued as an
// orphan so the next ApplyWatches call can retry the cleanup. Caller
// must hold a.mu.
func (a *Agent) installEntryLocked(st *entryState) error {
	rollbackRemove := func(reason error) error {
		if rerr := a.bpf.RemoveWatch(st.ip, st.entry.Port, st.entry.NodePort); rerr != nil {
			a.logger.Error(rerr, "rollback RemoveWatch failed; enqueueing orphan",
				"key", entryKey(&st.entry), "installErr", reason)
			a.orphans = append(a.orphans, &entryState{
				entry: st.entry,
				key:   st.key,
				ip:    st.ip,
			})
		}
		return reason
	}
	if _, err := a.bpf.AddWatch(st.ip, st.entry.Port, st.entry.NodePort); err != nil {
		return fmt.Errorf("AddWatch: %w", err)
	}
	if err := a.bpf.SetProxyMode(st.key, st.entry.ProxyMode, st.entry.NodePort); err != nil {
		return rollbackRemove(fmt.Errorf("SetProxyMode: %w", err))
	}
	if err := a.bpf.SetRstSuppress(st.key, st.entry.RstSuppress, st.entry.NodePort); err != nil {
		return rollbackRemove(fmt.Errorf("SetRstSuppress: %w", err))
	}
	return nil
}

// uninstallEntryLocked tears a single entry down. Caller must hold a.mu.
// RemoveWatch returns an errors.Join of every BPF map delete failure so the
// caller can either propagate (for the "phase 1 delete stale keys" loop)
// or enqueue the entry as an orphan (for the "phase 2 swap" loop).
func (a *Agent) uninstallEntryLocked(st *entryState) error {
	return a.bpf.RemoveWatch(st.ip, st.entry.Port, st.entry.NodePort)
}

// sweepOrphansLocked runs at the top of ApplyWatches and retries every
// previously-failed RemoveWatch. Successful orphans are dropped from the
// list; still-failing ones stay for the next pass. Retention is bounded
// only by the reconcile rate, so a permanently broken BPF map will keep
// the orphan forever — but that is also when the reconcile loop is
// already reporting errors to controller-runtime, so an operator has
// signal to intervene.
//
// Caller must hold a.mu.
func (a *Agent) sweepOrphansLocked() {
	if len(a.orphans) == 0 {
		return
	}
	kept := a.orphans[:0]
	for _, o := range a.orphans {
		if err := a.bpf.RemoveWatch(o.ip, o.entry.Port, o.entry.NodePort); err != nil {
			a.logger.V(1).Info("orphan RemoveWatch still failing",
				"key", entryKey(&o.entry), "error", err.Error())
			kept = append(kept, o)
			continue
		}
		a.logger.Info("orphan BPF state cleaned up",
			"key", entryKey(&o.entry),
			"ip", o.ip.String(),
			"nodePort", o.entry.NodePort)
	}
	a.orphans = kept
}

// indexInsertLocked / indexRemoveLocked keep the reverse-lookup indexes in
// sync with a.entries. Each (bpfKeyIndex, nodePortIndex) row is owned by
// exactly one entryState; updates never span multiple entries so the
// caller can treat them as atomic per key.
func (a *Agent) indexInsertLocked(st *entryState) {
	entry := st.entry // stable pointer copy
	a.bpfKeyIndex[st.key] = &entry
	if st.entry.NodePort > 0 {
		npKey := uint32(bpf.Htons(uint16(st.entry.NodePort)))
		a.nodePortIndex[npKey] = &entry
	}
}

func (a *Agent) indexRemoveLocked(st *entryState) {
	delete(a.bpfKeyIndex, st.key)
	if st.entry.NodePort > 0 {
		npKey := uint32(bpf.Htons(uint16(st.entry.NodePort)))
		delete(a.nodePortIndex, npKey)
	}
}

// ApplyWatches diffs the incoming set against the current state and installs
// the difference into BPF. The lock is held for the whole call so concurrent
// gRPC PutWatches requests serialise cleanly.
//
// Mutation semantics: when a logical key (namespace/service/port) already
// exists but the ClusterIP or NodePort changed, the new BPF state is
// installed FIRST, then the old BPF state is torn down. Doing it in that
// order means:
//
//  1. Every BPF-side operation for the new entry runs under the old entry's
//     coverage, so a mid-flight SYN cannot slip through unmonitored.
//  2. If any step of the new install fails, installEntryLocked rolls back
//     everything it touched and ApplyWatches returns an error WITHOUT
//     having disturbed the old entry — the caller retries on the next
//     reconcile and the agent's view stays consistent with BPF.
//
// The old BPF key and the new BPF key are distinct (different
// address / nodeport), so both coexist during the swap without colliding.
func (a *Agent) ApplyWatches(specs []WatchEntrySpec) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Before touching the desired set, retry any BPF teardowns that were
	// left in flight by a previous ApplyWatches error. This is how we
	// eventually converge on a clean state without having to abort the
	// whole reconcile pipeline or restart the pod.
	a.sweepOrphansLocked()

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

	// Phase 1: remove entries that are no longer desired. RemoveWatch
	// failures push the entry into the orphan list so the next ApplyWatches
	// can retry, instead of bailing out and leaving a half-deleted BPF
	// state that the caller can no longer reference.
	for k, st := range a.entries {
		if _, ok := want[k]; ok {
			continue
		}
		if err := a.uninstallEntryLocked(st); err != nil {
			a.logger.Error(err, "RemoveWatch on obsolete entry failed; enqueueing orphan",
				"key", k)
			a.orphans = append(a.orphans, st)
			a.indexRemoveLocked(st)
			delete(a.entries, k)
			return fmt.Errorf("RemoveWatch %s: %w", k, err)
		}
		a.indexRemoveLocked(st)
		delete(a.entries, k)
	}

	// Phase 2: install or update the desired entries atomically per key.
	for k, st := range want {
		old, hadOld := a.entries[k]
		if hadOld && old.ip.Equal(st.ip) && old.entry.NodePort == st.entry.NodePort {
			// Same address + same NodePort: no BPF-key mutation. Refresh
			// proxy_mode / rst_suppress but keep the per-key update
			// atomic: if SetRstSuppress fails after SetProxyMode has
			// already flipped, revert SetProxyMode back to the previously
			// stored value so BPF and a.entries do not disagree.
			prevProxy := old.entry.ProxyMode
			if err := a.bpf.SetProxyMode(st.key, st.entry.ProxyMode, st.entry.NodePort); err != nil {
				return fmt.Errorf("SetProxyMode %s: %w", k, err)
			}
			if err := a.bpf.SetRstSuppress(st.key, st.entry.RstSuppress, st.entry.NodePort); err != nil {
				if rerr := a.bpf.SetProxyMode(st.key, prevProxy, st.entry.NodePort); rerr != nil {
					a.logger.Error(rerr, "revert SetProxyMode failed; enqueueing orphan",
						"key", k, "rstSuppressErr", err)
					a.orphans = append(a.orphans, old)
				}
				return fmt.Errorf("SetRstSuppress %s: %w", k, err)
			}
			// Update the stored spec so DirectScale / target fields
			// follow the incoming data.
			a.entries[k] = st
			a.indexRemoveLocked(old)
			a.indexInsertLocked(st)
			continue
		}

		// Brand-new or mutation (ClusterIP / NodePort changed). Install
		// the new BPF state first; only on success tear down the old.
		if err := a.installEntryLocked(st); err != nil {
			return fmt.Errorf("install %s: %w", k, err)
		}
		if hadOld {
			if err := a.uninstallEntryLocked(old); err != nil {
				// New state is live; old one leaked. Keep going but
				// enqueue the old entryState as an orphan so the next
				// ApplyWatches can retry the teardown. Returning here
				// would leave BOTH entries installed and the caller
				// would probably redo installEntryLocked on retry,
				// duplicating the orphan state.
				a.logger.Error(err, "failed to tear down stale entry after swap; enqueueing orphan",
					"key", k, "oldIP", old.ip.String(), "newIP", st.ip.String())
				a.orphans = append(a.orphans, old)
			}
			a.indexRemoveLocked(old)
			a.logger.V(1).Info("swapped stale BPF state",
				"key", k,
				"oldIP", old.ip.String(), "newIP", st.ip.String(),
				"oldNodePort", old.entry.NodePort, "newNodePort", st.entry.NodePort)
		}
		a.entries[k] = st
		a.indexInsertLocked(st)
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
	defer func() {
		if err := reader.Close(); err != nil {
			a.logger.V(1).Info("ring buffer reader close failed", "error", err.Error())
		}
	}()
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
