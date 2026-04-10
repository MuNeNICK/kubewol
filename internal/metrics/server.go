// Package metrics serves the External Metrics API backed by BPF map data.
package metrics

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ServiceMetric holds the windowed SYN count for one service.
type ServiceMetric struct {
	Namespace string
	Service   string
	Count     uint64
}

// Provider is called to get the current windowed metrics.
type Provider func() []ServiceMetric

// Server serves the external.metrics.k8s.io API.
type Server struct {
	provider Provider
	mux      *http.ServeMux
}

// NewServer creates an External Metrics API server.
func NewServer(provider Provider) *Server {
	s := &Server{provider: provider}
	s.mux = http.NewServeMux()
	s.mux.HandleFunc("/apis/external.metrics.k8s.io/v1beta1", s.discoveryHandler)
	s.mux.HandleFunc("/apis/external.metrics.k8s.io/v1beta1/", s.metricsHandler)
	s.mux.HandleFunc("/apis", s.apiGroupsHandler)
	return s
}

// ListenAndServeTLS starts the HTTPS server with a self-signed cert.
func (s *Server) ListenAndServeTLS(addr string) error {
	tlsCfg, err := selfSignedTLS()
	if err != nil {
		return fmt.Errorf("tls: %w", err)
	}
	srv := &http.Server{Addr: addr, Handler: s.mux, TLSConfig: tlsCfg}
	return srv.ListenAndServeTLS("", "")
}

func (s *Server) metricsHandler(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/apis/external.metrics.k8s.io/v1beta1/"), "/")
	if len(parts) < 3 || parts[0] != "namespaces" {
		http.Error(w, "not found", 404)
		return
	}
	ns := parts[1]
	metricName := parts[2]
	if metricName != "ebpf_service_syn_total" {
		http.Error(w, "not found", 404)
		return
	}

	now := time.Now().UTC().Format(time.RFC3339)
	items := []map[string]any{}

	for _, m := range s.provider() {
		if m.Namespace != ns {
			continue
		}
		items = append(items, map[string]any{
			"metricName":   metricName,
			"metricLabels": map[string]string{"service": m.Service},
			"timestamp":    now,
			"value":        fmt.Sprintf("%d", m.Count),
		})
	}

	resp := map[string]any{
		"kind":       "ExternalMetricValueList",
		"apiVersion": "external.metrics.k8s.io/v1beta1",
		"metadata":   map[string]any{},
		"items":      items,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) discoveryHandler(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{
		"kind":         "APIResourceList",
		"apiVersion":   "v1",
		"groupVersion": "external.metrics.k8s.io/v1beta1",
		"resources": []map[string]any{{
			"name": "externalmetrics", "namespaced": true,
			"kind": "ExternalMetricValueList", "verbs": []string{"get"},
		}},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) apiGroupsHandler(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{
		"kind": "APIGroupList", "apiVersion": "v1",
		"groups": []map[string]any{{
			"name": "external.metrics.k8s.io",
			"versions": []map[string]string{
				{"groupVersion": "external.metrics.k8s.io/v1beta1", "version": "v1beta1"},
			},
			"preferredVersion": map[string]string{
				"groupVersion": "external.metrics.k8s.io/v1beta1", "version": "v1beta1",
			},
		}},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func selfSignedTLS() (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "kubewol"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"ebpf-monitor-api.monitoring.svc"},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
}

// Snapshotter computes windowed SYN counts from periodic cumulative snapshots.
type Snapshotter struct {
	mu     sync.RWMutex
	snaps  []snap
	window time.Duration
	maxN   int
}

type snap struct {
	ts     time.Time
	counts map[string]uint64
}

func NewSnapshotter(window time.Duration, interval time.Duration) *Snapshotter {
	n := int(window/interval) + 1
	if n < 2 {
		n = 2
	}
	return &Snapshotter{window: window, maxN: n}
}

// Record stores a new snapshot.
func (s *Snapshotter) Record(counts map[string]uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snaps = append(s.snaps, snap{ts: time.Now(), counts: counts})
	if len(s.snaps) > s.maxN {
		s.snaps = s.snaps[len(s.snaps)-s.maxN:]
	}
}

// Windowed returns the SYN increase per service key over the window.
func (s *Snapshotter) Windowed() map[string]uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.snaps) < 2 {
		if len(s.snaps) == 1 {
			return s.snaps[0].counts
		}
		return nil
	}
	newest := s.snaps[len(s.snaps)-1]
	oldest := s.snaps[0]
	result := make(map[string]uint64)
	for k, cur := range newest.counts {
		prev := oldest.counts[k]
		if cur > prev {
			result[k] = cur - prev
		}
	}
	return result
}
