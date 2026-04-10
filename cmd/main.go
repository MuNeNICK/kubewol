/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package main

import (
	"context"
	"flag"
	"net/http"
	"os"

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

	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "Health probe bind address.")
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":9090", "Prometheus /metrics bind address.")
	flag.StringVar(&remoteWriteURL, "remote-write-url", "",
		"Prometheus Remote Write URL (e.g. http://prometheus:9090/api/v1/write). "+
			"When set, metrics are pushed immediately on SYN detection for fast cold start.")

	opts := zap.Options{Development: true}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	// eBPF
	setupLog.Info("loading eBPF programs")
	bpfMgr, err := bpf.NewManager()
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
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		BPF:    bpfMgr,
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
	exporter := metrics.NewExporter(reconciler.MetricsProvider(), remoteWriteURL)

	// Prometheus /metrics HTTP server
	mux := http.NewServeMux()
	mux.Handle("/metrics", exporter.Handler())
	go func() {
		setupLog.Info("Prometheus exporter listening", "addr", metricsAddr)
		if err := http.ListenAndServe(metricsAddr, mux); err != nil {
			setupLog.Error(err, "metrics server failed")
		}
	}()

	// Ring buffer reader: log SYN events + trigger Remote Write push
	ctx := ctrl.SetupSignalHandler()
	go readSynEvents(ctx, bpfMgr, exporter)

	setupLog.Info("starting manager")
	if err := mgr.Start(ctx); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

func readSynEvents(ctx context.Context, bpfMgr *bpf.Manager, exporter *metrics.Exporter) {
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

	logger.Info("ring buffer reader started")
	for {
		evt, err := reader.ReadEvent()
		if err != nil {
			return
		}
		logger.V(1).Info("SYN detected",
			"src", evt.SrcAddr, "srcPort", evt.SrcPort,
			"dst", evt.DstAddr, "dstPort", evt.DstPort)

		// Push to Prometheus via Remote Write for fast cold start
		if err := exporter.PushRemoteWrite(); err != nil {
			logger.V(1).Info("remote write push failed", "error", err)
		}
	}
}
