// Package ebpf manages the TC eBPF programs and BPF maps.
package ebpf

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:embed monitor.o
var monitorBPF []byte

// SvcKey matches struct svc_key in monitor.c.
type SvcKey struct {
	Addr uint32
	Port uint16
	Pad  uint16
}

// SynEvent matches struct syn_event in monitor.c.
type SynEvent struct {
	SrcAddr uint32
	DstAddr uint32
	SrcPort uint16
	DstPort uint16
}

// Manager handles eBPF program loading, interface attachment, and map operations.
type Manager struct {
	coll  *ebpf.Collection
	links []link.Link
	mu    sync.Mutex
}

// NewManager loads the eBPF collection and attaches TC programs to all non-loopback interfaces.
func NewManager() (*Manager, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(monitorBPF))
	if err != nil {
		return nil, fmt.Errorf("load bpf spec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("create bpf collection: %w", err)
	}
	m := &Manager{coll: coll}
	if err := m.attachAll(); err != nil {
		coll.Close()
		return nil, err
	}
	return m, nil
}

func (m *Manager) attachAll() error {
	ifaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("list interfaces: %w", err)
	}
	ingressProg := m.coll.Programs["traffic_monitor"]
	if ingressProg == nil {
		return fmt.Errorf("bpf program 'traffic_monitor' not found")
	}
	egressProg := m.coll.Programs["rst_suppress"]
	if egressProg == nil {
		return fmt.Errorf("bpf program 'rst_suppress' not found")
	}
	attached := 0
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		li, err := link.AttachTCX(link.TCXOptions{
			Interface: iface.Index, Program: ingressProg, Attach: ebpf.AttachTCXIngress,
		})
		if err != nil {
			continue
		}
		m.links = append(m.links, li)
		le, err := link.AttachTCX(link.TCXOptions{
			Interface: iface.Index, Program: egressProg, Attach: ebpf.AttachTCXEgress,
		})
		if err == nil {
			m.links = append(m.links, le)
		}
		attached++
	}
	if attached == 0 {
		return fmt.Errorf("could not attach to any interface")
	}
	return nil
}

// Close detaches all programs and closes the collection.
func (m *Manager) Close() {
	for _, l := range m.links {
		l.Close()
	}
	m.coll.Close()
}

// SynCountMap returns the syn_count BPF map.
func (m *Manager) SynCountMap() *ebpf.Map { return m.coll.Maps["syn_count"] }

// SynEventsMap returns the syn_events ring buffer map.
func (m *Manager) SynEventsMap() *ebpf.Map { return m.coll.Maps["syn_events"] }

// AddWatch adds a ClusterIP:port to the BPF watch_svc map.
func (m *Manager) AddWatch(clusterIP net.IP, port uint16, nodePort int32) (SvcKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := SvcKey{Addr: IPToUint32(clusterIP), Port: Htons(port)}
	var val uint8 = 1
	if err := m.coll.Maps["watch_svc"].Update(key, val, ebpf.UpdateAny); err != nil {
		return key, fmt.Errorf("update watch_svc: %w", err)
	}
	if nodePort > 0 {
		npKey := uint32(Htons(uint16(nodePort)))
		m.coll.Maps["nodeport_mode"].Update(npKey, val, ebpf.UpdateAny)
		m.coll.Maps["nodeport_to_svc"].Update(npKey, key, ebpf.UpdateAny)
	}
	return key, nil
}

// RemoveWatch removes a ClusterIP:port from all BPF maps.
func (m *Manager) RemoveWatch(clusterIP net.IP, port uint16, nodePort int32) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := SvcKey{Addr: IPToUint32(clusterIP), Port: Htons(port)}
	m.coll.Maps["watch_svc"].Delete(key)
	m.coll.Maps["syn_count"].Delete(key)
	m.coll.Maps["proxy_mode"].Delete(key)
	if nodePort > 0 {
		npKey := uint32(Htons(uint16(nodePort)))
		m.coll.Maps["nodeport_mode"].Delete(npKey)
		m.coll.Maps["nodeport_to_svc"].Delete(npKey)
	}
}

// SetProxyMode enables or disables SYN DROP for a service.
func (m *Manager) SetProxyMode(key SvcKey, enabled bool, nodePort int32) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var val uint8
	if enabled {
		val = 1
	}
	m.coll.Maps["proxy_mode"].Update(key, val, ebpf.UpdateAny)
	if nodePort > 0 {
		npKey := uint32(Htons(uint16(nodePort)))
		m.coll.Maps["nodeport_mode"].Update(npKey, val, ebpf.UpdateAny)
	}
}

// ReadSynCount reads the cumulative SYN count for a key.
func (m *Manager) ReadSynCount(key SvcKey) uint64 {
	var count uint64
	if err := m.coll.Maps["syn_count"].Lookup(key, &count); err != nil {
		return 0
	}
	return count
}

// Helpers

func IPToUint32(ip net.IP) uint32 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
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
