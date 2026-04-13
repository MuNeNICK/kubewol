package controller

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics records controller-side operational signals for dashboards and alerting.
type Metrics struct {
	directScaleTotal    *prometheus.CounterVec
	directScaleDuration *prometheus.HistogramVec
	watchPushTotal      *prometheus.CounterVec
	agentClients        prometheus.Gauge
}

// NewMetrics registers controller-side metrics in the provided registry.
func NewMetrics(reg prometheus.Registerer) (*Metrics, error) {
	m := &Metrics{
		directScaleTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "kubewol_direct_scale_total",
				Help: "Direct-scale trigger outcomes grouped by result and target kind",
			},
			[]string{"result", "target_kind"},
		),
		directScaleDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "kubewol_direct_scale_duration_seconds",
				Help:    "Latency of direct-scale attempts grouped by result and target kind",
				Buckets: []float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30},
			},
			[]string{"result", "target_kind"},
		),
		watchPushTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "kubewol_watch_push_total",
				Help: "WatchSpec push outcomes from controller to the agent fleet",
			},
			[]string{"result"},
		),
		agentClients: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "kubewol_agent_clients",
				Help: "Currently connected kubewol agents discovered by the controller",
			},
		),
	}

	for _, collector := range []prometheus.Collector{
		m.directScaleTotal,
		m.directScaleDuration,
		m.watchPushTotal,
		m.agentClients,
	} {
		if err := reg.Register(collector); err != nil {
			return nil, err
		}
	}
	return m, nil
}

func (m *Metrics) ObserveDirectScale(result, targetKind string, duration time.Duration) {
	if m == nil {
		return
	}
	m.directScaleTotal.WithLabelValues(result, targetKind).Inc()
	m.directScaleDuration.WithLabelValues(result, targetKind).Observe(duration.Seconds())
}

func (m *Metrics) ObserveWatchPush(result string) {
	if m == nil {
		return
	}
	m.watchPushTotal.WithLabelValues(result).Inc()
}

func (m *Metrics) SetAgentClients(n int) {
	if m == nil {
		return
	}
	m.agentClients.Set(float64(n))
}
