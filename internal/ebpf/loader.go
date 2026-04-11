// Package ebpf manages the TC eBPF programs and BPF maps.
package ebpf

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/go-logr/logr"
)

//go:embed monitor.o
var monitorBPF []byte

// ErrIPv6Unsupported is returned when an IPv6 address is passed to AddWatch.
// The TC programs only parse IPv4.
var ErrIPv6Unsupported = errors.New("IPv6 services are not supported; TC programs parse IPv4 only")

// requiredMaps are the BPF map names the controller relies on.
// They are checked at startup to fail fast if the compiled monitor.o drifts.
var requiredMaps = []string{
	"watch_svc",
	"syn_count",
	"proxy_mode",
	"rst_suppress",
	"nodeport_mode",
	"nodeport_rst_suppress",
	"nodeport_to_svc",
	"syn_events",
	"drop_count",
}

// DropReason indexes into the drop_count BPF PERCPU_ARRAY. The values must
// match the #define block in bpf/monitor.c.
type DropReason uint32

const (
	DropReasonSynCountUpdate DropReason = 0
	DropReasonRingbufReserve DropReason = 1
)

// dropReasonNames is the label used in Prometheus for each reason.
var dropReasonNames = map[DropReason]string{
	DropReasonSynCountUpdate: "syn_count_update",
	DropReasonRingbufReserve: "ringbuf_reserve",
}

// SvcKey matches struct svc_key in monitor.c.
type SvcKey struct {
	Addr  uint32
	Port  uint16
	Proto uint8
	Pad   uint8
}

// NodePortKey matches struct nodeport_key in monitor.c.
type NodePortKey struct {
	Port  uint16
	Proto uint8
	Pad   uint8
}

// SynEvent matches struct syn_event in monitor.c.
type SynEvent struct {
	SrcAddr uint32
	DstAddr uint32
	SrcPort uint16
	DstPort uint16
	Proto   uint8
	Pad     [3]byte
}

const (
	ProtoTCP uint8 = 6
	ProtoUDP uint8 = 17
)

// Options configure optional behavior of the Manager.
type Options struct {
	// Logger receives diagnostic messages (attach failures, map drift, etc).
	Logger logr.Logger
	// InterfacePredicate selects which network interfaces to attach to.
	// If nil, all non-loopback interfaces are attached.
	InterfacePredicate func(iface net.Interface) bool
}

// attachedIface is the per-interface bookkeeping held by Manager.attached.
// Tracking the name alongside the ifindex lets attachNewInterfaces detect
// ifindex reuse (vanished veth → new veth with the same kernel ifindex)
// and close the stale links before re-attaching.
type attachedIface struct {
	name    string
	ingress link.Link
	egress  link.Link
}

// Manager handles eBPF program loading, interface attachment, and map operations.
type Manager struct {
	coll      *ebpf.Collection
	logger    logr.Logger
	mu        sync.Mutex
	predicate func(net.Interface) bool
	// attached tracks which interfaces currently have both TC programs
	// attached. Keyed by interface index. The stored value carries the
	// interface name and the two link handles so the poller in
	// attachNewInterfaces can detect ifindex reuse (by comparing the
	// current name against the stored one) and close the stale links.
	attached map[int]*attachedIface

	// Cached map handles. Set once in NewManager after verifying all required
	// maps are present. Eliminates nil-pointer panics from map name drift.
	m struct {
		watchSvc            *ebpf.Map
		synCount            *ebpf.Map
		proxyMode           *ebpf.Map
		rstSuppress         *ebpf.Map
		nodeportMode        *ebpf.Map
		nodeportRstSuppress *ebpf.Map
		nodeportToSvc       *ebpf.Map
		synEvents           *ebpf.Map
		dropCount           *ebpf.Map
	}
}

// NewManager loads the eBPF collection and attaches TC programs to network interfaces.
func NewManager(opts Options) (*Manager, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(monitorBPF))
	if err != nil {
		return nil, fmt.Errorf("load bpf spec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("create bpf collection: %w", err)
	}

	// Verify all required maps exist up-front. This converts object-name drift
	// from a runtime nil panic into a clean startup error.
	for _, name := range requiredMaps {
		if coll.Maps[name] == nil {
			coll.Close()
			return nil, fmt.Errorf("bpf map %q not found in object", name)
		}
	}

	m := &Manager{
		coll:      coll,
		logger:    opts.Logger,
		predicate: opts.InterfacePredicate,
		attached:  make(map[int]*attachedIface),
	}
	m.m.watchSvc = coll.Maps["watch_svc"]
	m.m.synCount = coll.Maps["syn_count"]
	m.m.proxyMode = coll.Maps["proxy_mode"]
	m.m.rstSuppress = coll.Maps["rst_suppress"]
	m.m.nodeportMode = coll.Maps["nodeport_mode"]
	m.m.nodeportRstSuppress = coll.Maps["nodeport_rst_suppress"]
	m.m.nodeportToSvc = coll.Maps["nodeport_to_svc"]
	m.m.synEvents = coll.Maps["syn_events"]
	m.m.dropCount = coll.Maps["drop_count"]

	if err := m.attachAll(); err != nil {
		coll.Close()
		return nil, err
	}
	return m, nil
}

// attachAll attaches ingress AND egress TC programs to every selected non-loopback
// interface currently present. Startup mode: requires at least one interface to
// attach successfully. Subsequent runs via WatchInterfaces are best-effort.
func (m *Manager) attachAll() error {
	attached, err := m.attachNewInterfaces()
	if err != nil {
		return err
	}
	if attached == 0 {
		return fmt.Errorf("could not attach to any interface (ingress+egress required)")
	}
	return nil
}

// attachNewInterfaces scans the current interface list and attaches TC programs
// to any interface that matches the predicate and is not already attached.
// Returns the number of interfaces attached in this call.
//
// This is the entry point for both startup attach and dynamic attach of veth
// pairs created after kubewol starts. Without dynamic attach, a Pod created
// after startup would have no RST suppression on its veth: kube-proxy REJECT
// for a scaled-to-zero Service would deliver a TCP RST back to the new Pod
// via a veth that has no egress filter, and the cold-start behaviour breaks.
func (m *Manager) attachNewInterfaces() (int, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return 0, fmt.Errorf("list interfaces: %w", err)
	}
	ingressProg := m.coll.Programs["traffic_monitor"]
	if ingressProg == nil {
		return 0, fmt.Errorf("bpf program 'traffic_monitor' not found")
	}
	egressProg := m.coll.Programs["egress_rst_filter"]
	if egressProg == nil {
		return 0, fmt.Errorf("bpf program 'egress_rst_filter' not found")
	}

	// Snapshot the current interface list into a (index -> name) map
	// so we can detect ifindex reuse while holding the Manager lock.
	live := make(map[int]string, len(ifaces))
	for _, iface := range ifaces {
		live[iface.Index] = iface.Name
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Prune stale entries: either the ifindex is gone entirely, or it has
	// been reused by a different interface (new name). Close the old
	// link handles in both cases so the next attach pass can re-attach
	// a fresh pair on the reused ifindex.
	for idx, st := range m.attached {
		curName, alive := live[idx]
		if alive && curName == st.name {
			continue
		}
		if st.ingress != nil {
			_ = st.ingress.Close()
		}
		if st.egress != nil {
			_ = st.egress.Close()
		}
		reason := "vanished"
		if alive {
			reason = "ifindex reused"
		}
		m.logger.Info("TC detached",
			"iface", st.name, "index", idx, "reason", reason)
		delete(m.attached, idx)
	}

	attached := 0
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if m.predicate != nil && !m.predicate(iface) {
			continue
		}
		if st, ok := m.attached[iface.Index]; ok && st.name == iface.Name {
			continue
		}
		li, err := link.AttachTCX(link.TCXOptions{
			Interface: iface.Index, Program: ingressProg, Attach: ebpf.AttachTCXIngress,
		})
		if err != nil {
			m.logger.V(1).Info("TC ingress attach failed", "iface", iface.Name, "error", err.Error())
			continue
		}
		le, err := link.AttachTCX(link.TCXOptions{
			Interface: iface.Index, Program: egressProg, Attach: ebpf.AttachTCXEgress,
		})
		if err != nil {
			m.logger.V(1).Info("TC egress attach failed, rolling back ingress",
				"iface", iface.Name, "error", err.Error())
			_ = li.Close()
			continue
		}
		m.attached[iface.Index] = &attachedIface{
			name:    iface.Name,
			ingress: li,
			egress:  le,
		}
		m.logger.Info("TC attached", "iface", iface.Name, "index", iface.Index)
		attached++
	}
	return attached, nil
}

// WatchInterfaces polls for new interfaces and attaches TC programs to them.
// Run this as a goroutine for the lifetime of the process.
//
// Polling is used instead of netlink RTM_NEWLINK because a 1s poll is cheap
// (one getifaddrs syscall) and avoids a new dependency. A newly-created Pod's
// RST-suppression coverage gap is at most one poll interval, which is well
// below the kernel's ~1s first TCP SYN retransmit, so the client still sees
// a transparent cold start as long as the attach happens within that window.
func (m *Manager) WatchInterfaces(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := m.attachNewInterfaces(); err != nil {
				m.logger.V(1).Info("dynamic attach scan failed", "error", err.Error())
			}
		}
	}
}

// Close detaches all programs and closes the collection.
func (m *Manager) Close() {
	m.mu.Lock()
	for idx, st := range m.attached {
		if st.ingress != nil {
			_ = st.ingress.Close()
		}
		if st.egress != nil {
			_ = st.egress.Close()
		}
		delete(m.attached, idx)
	}
	m.mu.Unlock()
	m.coll.Close()
}

// SynEventsMap returns the syn_events ring buffer map.
func (m *Manager) SynEventsMap() *ebpf.Map { return m.m.synEvents }

// AddWatch registers a ClusterIP:port in the BPF watch map so the TC program
// starts counting SYNs to it. It does NOT enable proxy_mode or nodeport_mode;
// those are separately controlled by SetProxyMode / SetRstSuppress and are
// only turned on when there are zero ready endpoints.
//
// The nodeport_to_svc map IS populated here because it is a static lookup
// table (NodePort -> ClusterIP key), independent of proxy state.
func (m *Manager) AddWatch(clusterIP net.IP, port uint16, nodePort int32, protocol string) (SvcKey, error) {
	if clusterIP.To4() == nil {
		return SvcKey{}, ErrIPv6Unsupported
	}
	proto, ok := ProtocolNumber(protocol)
	if !ok {
		return SvcKey{}, fmt.Errorf("unsupported protocol %q", protocol)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	key := SvcKey{Addr: ipToUint32(clusterIP), Port: Htons(port), Proto: proto}
	var val uint8 = 1
	if err := m.m.watchSvc.Update(key, val, ebpf.UpdateAny); err != nil {
		return key, fmt.Errorf("update watch_svc: %w", err)
	}
	if nodePort > 0 {
		npKey := MakeNodePortKey(uint16(nodePort), proto)
		if err := m.m.nodeportToSvc.Update(npKey, key, ebpf.UpdateAny); err != nil {
			// Roll back watch_svc to avoid partial state.
			_ = m.m.watchSvc.Delete(key)
			return key, fmt.Errorf("update nodeport_to_svc: %w", err)
		}
	}
	return key, nil
}

// RemoveWatch removes a ClusterIP:port from all BPF maps.
// Errors are aggregated and returned.
func (m *Manager) RemoveWatch(clusterIP net.IP, port uint16, nodePort int32, protocol string) error {
	if clusterIP.To4() == nil {
		return nil
	}
	proto, ok := ProtocolNumber(protocol)
	if !ok {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	key := SvcKey{Addr: ipToUint32(clusterIP), Port: Htons(port), Proto: proto}
	var errs []error
	del := func(mapName string, target *ebpf.Map, k any) {
		if err := target.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, fmt.Errorf("%s delete: %w", mapName, err))
		}
	}
	del("watch_svc", m.m.watchSvc, key)
	del("syn_count", m.m.synCount, key)
	del("proxy_mode", m.m.proxyMode, key)
	del("rst_suppress", m.m.rstSuppress, key)
	if nodePort > 0 {
		npKey := MakeNodePortKey(uint16(nodePort), proto)
		del("nodeport_mode", m.m.nodeportMode, npKey)
		del("nodeport_rst_suppress", m.m.nodeportRstSuppress, npKey)
		del("nodeport_to_svc", m.m.nodeportToSvc, npKey)
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// SetProxyMode enables or disables SYN DROP for a service (ingress).
// When disabled, entries are DELETED (not set to 0) so they do not accumulate
// as tombstones against the 256-entry hash map capacity.
//
// When nodePort > 0, both maps are updated together. If the NodePort update fails,
// the ClusterIP update is rolled back so the two paths cannot disagree.
func (m *Manager) SetProxyMode(key SvcKey, enabled bool, nodePort int32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.setDual(m.m.proxyMode, "proxy_mode", m.m.nodeportMode, "nodeport_mode", key, nodePort, enabled)
}

// SetRstSuppress enables or disables RST/ICMP suppression (egress).
// Same atomicity guarantee as SetProxyMode.
func (m *Manager) SetRstSuppress(key SvcKey, enabled bool, nodePort int32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.setDual(m.m.rstSuppress, "rst_suppress", m.m.nodeportRstSuppress, "nodeport_rst_suppress", key, nodePort, enabled)
}

// setDual updates the ClusterIP-keyed map and (if nodePort > 0) the NodePort-keyed
// map in a pseudo-atomic way: if the second update fails, the first is reverted.
// enabled=false performs deletes (tombstone-free).
func (m *Manager) setDual(
	ipMap *ebpf.Map, ipMapName string,
	npMap *ebpf.Map, npMapName string,
	key SvcKey, nodePort int32, enabled bool,
) error {
	// Read the prior IP-key state so we can roll back on NodePort failure.
	var prior uint8
	hadPrior := true
	if err := ipMap.Lookup(key, &prior); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			hadPrior = false
		} else {
			return fmt.Errorf("lookup %s: %w", ipMapName, err)
		}
	}

	// Update the ClusterIP-keyed entry.
	if enabled {
		if err := ipMap.Update(key, uint8(1), ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update %s: %w", ipMapName, err)
		}
	} else if hadPrior {
		if err := ipMap.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete %s: %w", ipMapName, err)
		}
	}

	if nodePort <= 0 {
		return nil
	}
	npKey := MakeNodePortKey(uint16(nodePort), key.Proto)

	rollback := func() error {
		if hadPrior {
			if err := ipMap.Update(key, prior, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("rollback %s: %w", ipMapName, err)
			}
			return nil
		}
		if err := ipMap.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("rollback %s: %w", ipMapName, err)
		}
		return nil
	}

	// Update the NodePort-keyed entry; roll back the IP entry on failure and
	// surface BOTH the original error and any rollback failure to the caller.
	if enabled {
		if err := npMap.Update(npKey, uint8(1), ebpf.UpdateAny); err != nil {
			origErr := fmt.Errorf("update %s: %w", npMapName, err)
			if rerr := rollback(); rerr != nil {
				return errors.Join(origErr, rerr)
			}
			return origErr
		}
		return nil
	}
	if err := npMap.Delete(npKey); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		origErr := fmt.Errorf("delete %s: %w", npMapName, err)
		if rerr := rollback(); rerr != nil {
			return errors.Join(origErr, rerr)
		}
		return origErr
	}
	return nil
}

// DropCounts reads the per-reason PERCPU_ARRAY and returns a label->count
// map suitable for Prometheus export. A missing map yields an empty result.
func (m *Manager) DropCounts() (map[string]uint64, error) {
	out := map[string]uint64{}
	if m.m.dropCount == nil {
		return out, nil
	}
	for reason, label := range dropReasonNames {
		var perCPU []uint64
		key := uint32(reason)
		if err := m.m.dropCount.Lookup(key, &perCPU); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				continue
			}
			return nil, fmt.Errorf("lookup drop_count[%s]: %w", label, err)
		}
		var total uint64
		for _, v := range perCPU {
			total += v
		}
		out[label] = total
	}
	return out, nil
}

// ReadPacketCount reads the cumulative wake-packet count for a key.
// A missing entry yields (0, nil); real lookup errors are surfaced.
func (m *Manager) ReadPacketCount(key SvcKey) (uint64, error) {
	var count uint64
	if err := m.m.synCount.Lookup(key, &count); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return 0, nil
		}
		return 0, fmt.Errorf("lookup syn_count: %w", err)
	}
	return count, nil
}

// ProtocolNumber converts a Kubernetes Service protocol string to the IP
// protocol number stored in BPF map keys. Empty is treated as TCP because that
// is the Kubernetes default for Service ports.
func ProtocolNumber(protocol string) (uint8, bool) {
	switch protocol {
	case "", "TCP":
		return ProtoTCP, true
	case "UDP":
		return ProtoUDP, true
	default:
		return 0, false
	}
}

// MakeNodePortKey builds the protocol-aware NodePort map key used by BPF.
func MakeNodePortKey(port uint16, proto uint8) NodePortKey {
	return NodePortKey{Port: Htons(port), Proto: proto}
}

// Helpers

// IPToUint32 converts an IPv4 address to its raw uint32 representation.
// Returns (0, false) for non-IPv4 inputs.
func IPToUint32(ip net.IP) (uint32, bool) {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0, false
	}
	return ipToUint32(ip), true
}

// IPToUint32Must is a convenience for callers that have already validated the IP.
// Panics if the IP is not IPv4. Use IPToUint32 for unvalidated input.
func IPToUint32Must(ip net.IP) uint32 {
	v, ok := IPToUint32(ip)
	if !ok {
		panic("IPToUint32Must: non-IPv4 address")
	}
	return v
}

// ipToUint32 is the unchecked conversion (IPv4 assumed). Private helper.
func ipToUint32(ip net.IP) uint32 {
	ip4 := ip.To4()
	return *(*uint32)(unsafe.Pointer(&ip4[0]))
}

func Uint32ToIP(n uint32) net.IP {
	b := make([]byte, 4)
	*(*uint32)(unsafe.Pointer(&b[0])) = n
	return net.IP(b)
}

func Htons(v uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}

func Ntohs(v uint16) uint16 {
	b := (*[2]byte)(unsafe.Pointer(&v))
	return binary.BigEndian.Uint16(b[:])
}
