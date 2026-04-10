// Package metrics provides a Prometheus exporter and Remote Write pusher
// for eBPF SYN count metrics.
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
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// ServiceMetric holds the current SYN count for a service.
type ServiceMetric struct {
	Namespace string
	Service   string
	Count     uint64
}

// Provider is called to get current metrics.
type Provider func() []ServiceMetric

// Exporter exposes Prometheus /metrics and pushes via Remote Write on demand.
type Exporter struct {
	provider       Provider
	remoteWriteURL string
	desc           *prometheus.Desc
	pushMu         sync.Mutex
}

// NewExporter creates a Prometheus exporter.
// remoteWriteURL can be empty to disable Remote Write push.
func NewExporter(provider Provider, remoteWriteURL string) *Exporter {
	return &Exporter{
		provider:       provider,
		remoteWriteURL: remoteWriteURL,
		desc: prometheus.NewDesc(
			"ebpf_service_syn_total",
			"TCP SYN packets observed by eBPF for a Kubernetes service",
			[]string{"namespace", "service"}, nil,
		),
	}
}

// Describe implements prometheus.Collector.
func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- e.desc
}

// Collect implements prometheus.Collector.
func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	for _, m := range e.provider() {
		ch <- prometheus.MustNewConstMetric(
			e.desc, prometheus.CounterValue, float64(m.Count),
			m.Namespace, m.Service,
		)
	}
}

// Handler returns the Prometheus HTTP handler.
func (e *Exporter) Handler() http.Handler {
	reg := prometheus.NewRegistry()
	reg.MustRegister(e)
	return promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
}

// PushRemoteWrite sends current metrics to Prometheus via Remote Write.
// Call on SYN detection for fast metric delivery (bypasses scrape interval).
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
		{"__name__", "ebpf_service_syn_total"},
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
