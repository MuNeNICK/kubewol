/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package main

import (
	"context"
	"flag"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/munenick/kubewol/internal/controller"
	bpf "github.com/munenick/kubewol/internal/ebpf"
	"github.com/munenick/kubewol/internal/metrics"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
}

func main() {
	var probeAddr string
	var metricsAddr string
	var remoteWriteURL string
	var ifaceAllow string
	var ifaceDeny string

	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "Health probe bind address.")
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":9090", "Prometheus /metrics bind address.")
	flag.StringVar(&remoteWriteURL, "remote-write-url", "",
		"Prometheus Remote Write URL (e.g. http://prometheus:9090/api/v1/write). "+
			"When set, metrics are pushed immediately on SYN detection for fast cold start.")
	flag.StringVar(&ifaceAllow, "tc-iface-allow", "",
		"Comma-separated interface name prefixes to attach TC programs to. "+
			"Empty means attach to every non-loopback interface. Use this on CNIs "+
			"that bridge traffic through an intermediate interface (e.g. 'cni0,eth0') "+
			"to avoid double-counting SYN packets.")
	flag.StringVar(&ifaceDeny, "tc-iface-deny", "",
		"Comma-separated interface name prefixes to EXCLUDE from TC attach. "+
			"Evaluated after --tc-iface-allow.")

	opts := zap.Options{Development: true}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	predicate := buildInterfacePredicate(ifaceAllow, ifaceDeny)

	// eBPF
	setupLog.Info("loading eBPF programs",
		"ifaceAllow", ifaceAllow, "ifaceDeny", ifaceDeny)
	bpfMgr, err := bpf.NewManager(bpf.Options{
		Logger:             ctrl.Log.WithName("ebpf"),
		InterfacePredicate: predicate,
	})
	if err != nil {
		setupLog.Error(err, "failed to init eBPF")
		os.Exit(1)
	}
	defer bpfMgr.Close()
	setupLog.Info("eBPF programs loaded and attached")

	// Controller manager (disable built-in metrics, we serve our own)
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         false, // DaemonSet, each pod runs independently
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	reconciler := &controller.ScaleToZeroReconciler{
		Client:    mgr.GetClient(),
		APIReader: mgr.GetAPIReader(),
		Scheme:    mgr.GetScheme(),
		BPF:       bpfMgr,
	}
	if err := reconciler.SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	// Prometheus exporter + Remote Write
	exporter := metrics.NewExporter(
		reconciler.MetricsProvider(),
		bpfMgr.DropCounts,
		remoteWriteURL,
	)

	// Prometheus /metrics HTTP server.
	// SECURITY: this endpoint is unauthenticated. With hostNetwork: true the
	// process binds 0.0.0.0:metricsAddr on the node, so anything on the node
	// network can scrape it. Apply config/network-policy/allow-metrics-traffic.yaml
	// (or an equivalent NetworkPolicy) to restrict access to your Prometheus
	// namespace. See README "Securing the metrics endpoint" for details.
	mux := http.NewServeMux()
	mux.Handle("/metrics", exporter.Handler())
	go func() {
		setupLog.Info("Prometheus exporter listening (UNAUTHENTICATED, restrict via NetworkPolicy)",
			"addr", metricsAddr)
		if err := http.ListenAndServe(metricsAddr, mux); err != nil {
			setupLog.Error(err, "metrics server failed")
		}
	}()

	// Ring buffer reader: log SYN events + trigger Remote Write push + direct scale
	ctx := ctrl.SetupSignalHandler()
	go readSynEvents(ctx, bpfMgr, exporter, reconciler)
	// Dynamic TC attach: Pods created after startup get new veth pairs and need
	// programs attached to them or RST suppression is skipped for their traffic.
	go bpfMgr.WatchInterfaces(ctx, time.Second)

	setupLog.Info("starting manager")
	if err := mgr.Start(ctx); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

// buildInterfacePredicate returns an interface filter for TC attach, honoring
// the --tc-iface-allow and --tc-iface-deny prefix lists. Empty allow means
// "match any non-loopback"; non-empty allow means "must have a matching prefix".
// Deny is always applied after allow.
func buildInterfacePredicate(allowCSV, denyCSV string) func(net.Interface) bool {
	allow := splitPrefixes(allowCSV)
	deny := splitPrefixes(denyCSV)
	if len(allow) == 0 && len(deny) == 0 {
		return nil
	}
	return func(iface net.Interface) bool {
		name := iface.Name
		if len(allow) > 0 {
			matched := false
			for _, p := range allow {
				if strings.HasPrefix(name, p) {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		}
		for _, p := range deny {
			if strings.HasPrefix(name, p) {
				return false
			}
		}
		return true
	}
}

func splitPrefixes(csv string) []string {
	if csv == "" {
		return nil
	}
	parts := strings.Split(csv, ",")
	out := parts[:0]
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// scaleJob is queued to the bounded worker pool when a SYN event hints
// at a direct-scale opportunity.
type scaleJob struct {
	namespace string
	kind      string
	name      string
}

func readSynEvents(
	ctx context.Context,
	bpfMgr *bpf.Manager,
	exporter *metrics.Exporter,
	reconciler *controller.ScaleToZeroReconciler,
) {
	eventsMap := bpfMgr.SynEventsMap()
	if eventsMap == nil {
		return
	}
	logger := ctrl.Log.WithName("syn-events")

	reader, err := newRingbufReader(eventsMap)
	if err != nil {
		logger.Error(err, "failed to create ringbuf reader")
		return
	}
	defer reader.Close()
	go func() { <-ctx.Done(); reader.Close() }()

	// Bounded worker pool for direct-scale triggers. A small pool is enough because
	// TriggerScale is debounced per-target and is short-lived (few ms in the hot path).
	// A bounded buffered channel provides backpressure: if workers fall behind under
	// a SYN burst, we drop redundant jobs rather than spawning unbounded goroutines.
	const scaleWorkers = 4
	const scaleQueueDepth = 64
	scaleCh := make(chan scaleJob, scaleQueueDepth)
	for i := 0; i < scaleWorkers; i++ {
		go func() {
			for job := range scaleCh {
				reconciler.TriggerScale(ctx, job.namespace, job.kind, job.name)
			}
		}()
	}
	defer close(scaleCh)

	logger.Info("ring buffer reader started")
	for {
		evt, err := reader.ReadEvent()
		if err != nil {
			return
		}
		logger.V(1).Info("SYN detected",
			"src", bpf.Uint32ToIP(evt.SrcAddr).String(),
			"srcPort", bpf.Ntohs(evt.SrcPort),
			"dst", bpf.Uint32ToIP(evt.DstAddr).String(),
			"dstPort", bpf.Ntohs(evt.DstPort))

		// Push to Prometheus via Remote Write for fast cold start
		if err := exporter.PushRemoteWrite(); err != nil {
			logger.V(1).Info("remote write push failed", "error", err)
		}

		// Direct scale trigger (opt-in via kubewol/direct-scale annotation)
		if entry := reconciler.LookupByBPFKey(evt.DstAddr, evt.DstPort); entry != nil {
			select {
			case scaleCh <- scaleJob{
				namespace: entry.Namespace,
				kind:      entry.TargetKind,
				name:      entry.TargetName,
			}:
			default:
				// Queue is full; a previous event for the same target is either
				// in-flight or already debounced. Drop.
				logger.V(1).Info("scale queue full, dropping SYN event",
					"target", entry.Namespace+"/"+entry.TargetName)
			}
		}
	}
}
