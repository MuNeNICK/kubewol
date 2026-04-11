// Package metrics provides a Prometheus exporter and Remote Write pusher
// for eBPF wake-packet metrics.
package metrics

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/golang/snappy"
	"github.com/prometheus/client_golang/prometheus"
)

// ServiceMetric holds the current wake-packet count for a service.
type ServiceMetric struct {
	Namespace string
	Service   string
	Count     uint64
}

// Provider is called to get current metrics.
type Provider func() []ServiceMetric

// DropProvider returns per-reason BPF drop counts (label -> total).
// Kernel side increments drop_count[] via drop_inc() when a BPF map update
// or ringbuf reserve fails; this surfaces those otherwise-silent failures.
type DropProvider func() (map[string]uint64, error)

// Exporter exposes Prometheus /metrics and pushes via Remote Write on demand.
//
// The exporter implements prometheus.Collector and is registered with the
// controller-runtime shared metrics registry in main.go, so /metrics is served
// by the controller-runtime metrics server (with built-in TLS + TokenReview
// authentication) rather than a hand-rolled HTTP listener.
type Exporter struct {
	provider       Provider
	dropProvider   DropProvider
	remoteWriteURL string
	desc           *prometheus.Desc
	dropDesc       *prometheus.Desc
	pushMu         sync.Mutex
}

// NewExporter creates a Prometheus exporter.
// remoteWriteURL can be empty to disable Remote Write push.
// dropProvider can be nil to skip exporting BPF drop counters.
func NewExporter(provider Provider, dropProvider DropProvider, remoteWriteURL string) *Exporter {
	return &Exporter{
		provider:       provider,
		dropProvider:   dropProvider,
		remoteWriteURL: remoteWriteURL,
		desc: prometheus.NewDesc(
			"ebpf_service_packets_total",
			"Wake-triggering packets observed by eBPF for a Kubernetes service",
			[]string{"namespace", "service"}, nil,
		),
		dropDesc: prometheus.NewDesc(
			"kubewol_bpf_drop_total",
			"BPF hot-path failures (e.g. map-full, ringbuf-full) grouped by reason",
			[]string{"reason"}, nil,
		),
	}
}

// Register adds this exporter to the given Prometheus registry. Use this to
// attach the eBPF metrics to controller-runtime's shared metrics.Registry.
func (e *Exporter) Register(reg prometheus.Registerer) error {
	return reg.Register(e)
}

// Describe implements prometheus.Collector.
func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- e.desc
	ch <- e.dropDesc
}

// Collect implements prometheus.Collector.
func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	for _, m := range e.provider() {
		ch <- prometheus.MustNewConstMetric(
			e.desc, prometheus.CounterValue, float64(m.Count),
			m.Namespace, m.Service,
		)
	}
	if e.dropProvider == nil {
		return
	}
	drops, err := e.dropProvider()
	if err != nil {
		return
	}
	for reason, count := range drops {
		ch <- prometheus.MustNewConstMetric(
			e.dropDesc, prometheus.CounterValue, float64(count), reason,
		)
	}
}

// PushRemoteWrite sends current metrics to Prometheus via Remote Write.
// Call on packet detection for fast metric delivery (bypasses scrape interval).
func (e *Exporter) PushRemoteWrite() error {
	if e.remoteWriteURL == "" {
		return nil
	}
	e.pushMu.Lock()
	defer e.pushMu.Unlock()

	metrics := e.provider()
	if len(metrics) == 0 {
		return nil
	}

	now := time.Now().UnixMilli()
	data := encodeWriteRequest(metrics, now)
	compressed := snappy.Encode(nil, data)

	req, err := http.NewRequest("POST", e.remoteWriteURL, bytes.NewReader(compressed))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("Content-Encoding", "snappy")
	req.Header.Set("X-Prometheus-Remote-Write-Version", "0.1.0")

	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("remote write: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("remote write: status %d", resp.StatusCode)
	}
	return nil
}

// ── Minimal protobuf encoder for Prometheus Remote Write ──
//
// WriteRequest { repeated TimeSeries timeseries = 1 }
// TimeSeries   { repeated Label labels = 1; repeated Sample samples = 2 }
// Label        { string name = 1; string value = 2 }
// Sample       { double value = 1; int64 timestamp = 2 }

func encodeWriteRequest(metrics []ServiceMetric, timestampMs int64) []byte {
	var buf bytes.Buffer
	for _, m := range metrics {
		ts := encodeTimeSeries(m, timestampMs)
		writeTag(&buf, 1, 2) // field 1, wire type 2 (length-delimited)
		writeBytes(&buf, ts)
	}
	return buf.Bytes()
}

func encodeTimeSeries(m ServiceMetric, ts int64) []byte {
	var buf bytes.Buffer
	// labels
	for _, lbl := range [][2]string{
		{"__name__", "ebpf_service_packets_total"},
		{"namespace", m.Namespace},
		{"service", m.Service},
	} {
		l := encodeLabel(lbl[0], lbl[1])
		writeTag(&buf, 1, 2)
		writeBytes(&buf, l)
	}
	// sample
	s := encodeSample(float64(m.Count), ts)
	writeTag(&buf, 2, 2)
	writeBytes(&buf, s)
	return buf.Bytes()
}

func encodeLabel(name, value string) []byte {
	var buf bytes.Buffer
	writeTag(&buf, 1, 2)
	writeBytes(&buf, []byte(name))
	writeTag(&buf, 2, 2)
	writeBytes(&buf, []byte(value))
	return buf.Bytes()
}

func encodeSample(value float64, timestampMs int64) []byte {
	var buf bytes.Buffer
	// double value = 1 (wire type 1 = fixed 64-bit)
	writeTag(&buf, 1, 1)
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, math.Float64bits(value))
	buf.Write(b)
	// int64 timestamp = 2 (wire type 0 = varint)
	writeTag(&buf, 2, 0)
	writeVarint(&buf, timestampMs)
	return buf.Bytes()
}

func writeTag(buf *bytes.Buffer, field int, wireType int) {
	writeUvarint(buf, uint64(field<<3|wireType))
}

func writeBytes(buf *bytes.Buffer, data []byte) {
	writeUvarint(buf, uint64(len(data)))
	buf.Write(data)
}

func writeVarint(buf *bytes.Buffer, v int64) {
	writeUvarint(buf, uint64(v))
}

func writeUvarint(buf *bytes.Buffer, v uint64) {
	var b [10]byte
	n := binary.PutUvarint(b[:], v)
	buf.Write(b[:n])
}
