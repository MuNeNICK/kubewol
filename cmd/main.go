/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package main

import (
	"context"
	"flag"
	"os"
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
	// +kubebuilder:scaffold:imports
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
	var metricsAPIAddr string
	var snapInterval time.Duration
	var snapWindow time.Duration

	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "Health probe bind address.")
	flag.StringVar(&metricsAPIAddr, "external-metrics-addr", ":6443", "External Metrics API HTTPS bind address.")
	flag.DurationVar(&snapInterval, "snap-interval", 10*time.Second, "Snapshot interval for windowed SYN counts.")
	flag.DurationVar(&snapWindow, "snap-window", 60*time.Second, "Window duration for SYN count reporting.")

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

	// Snapshotter
	snap := metrics.NewSnapshotter(snapWindow, snapInterval)

	// Controller manager (disable built-in metrics to avoid port conflict)
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: "0"}, // disabled
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         false, // DaemonSet, each pod reconciles locally
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	reconciler := &controller.ScaleToZeroReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		BPF:    bpfMgr,
		Snap:   snap,
	}
	if err := reconciler.SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller")
		os.Exit(1)
	}
	// +kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	// Snapshot loop
	ctx := ctrl.SetupSignalHandler()
	go func() {
		ticker := time.NewTicker(snapInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				reconciler.RecordSnapshot()
			}
		}
	}()

	// External Metrics API server
	apiSrv := metrics.NewServer(reconciler.MetricsProvider())
	go func() {
		setupLog.Info("starting External Metrics API", "addr", metricsAPIAddr)
		if err := apiSrv.ListenAndServeTLS(metricsAPIAddr); err != nil {
			setupLog.Error(err, "external metrics API server failed")
		}
	}()

	// Ring buffer reader (logging only, scale is HPA's job)
	go readSynEvents(ctx, bpfMgr)

	setupLog.Info("starting manager")
	if err := mgr.Start(ctx); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

func readSynEvents(ctx context.Context, bpfMgr *bpf.Manager) {
	eventsMap := bpfMgr.SynEventsMap()
	if eventsMap == nil {
		return
	}
	logger := ctrl.Log.WithName("syn-events")

	// Use ringbuf reader
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
			return // closed
		}
		logger.Info("SYN detected",
			"src", evt.SrcAddr, "srcPort", evt.SrcPort,
			"dst", evt.DstAddr, "dstPort", evt.DstPort)
	}
}
