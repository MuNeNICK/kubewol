/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
	metricsfilters "sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/munenick/kubewol/internal/agent"
	pb "github.com/munenick/kubewol/internal/agentapi/pb"
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

// agentGRPCAddr is the bind address the agent's gRPC listener uses. Kept as a
// package-level variable so runAgent can read the flag after main() parses.
var (
	agentGRPCAddr       string
	agentTLSCertFile    string
	agentTLSKeyFile     string
	agentAllowedCallers string
)

func main() {
	var mode string
	var probeAddr string
	var metricsAddr string
	var remoteWriteURL string
	var ifaceAllow string
	var ifaceDeny string
	var agentNamespace string
	var agentService string
	var agentPort int
	var agentTLSCAFile string
	var agentTLSServerName string

	flag.StringVar(&mode, "mode", "agent",
		"Component to run. 'agent' loads eBPF and serves the kubewol.v1.Agent "+
			"gRPC service. 'controller' runs the reconciler and the direct-scale "+
			"fast path; it must be able to reach every agent over the pod network.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "Health probe bind address.")
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8443",
		"HTTPS metrics / agent-API bind address. Served by controller-runtime "+
			"with TLS + TokenReview auth.")
	flag.StringVar(&remoteWriteURL, "remote-write-url", "",
		"Prometheus Remote Write URL. Agent-only. When set, the agent pushes "+
			"its local metrics snapshot on each direct-scale SYN for fast cold start.")
	flag.StringVar(&ifaceAllow, "tc-iface-allow", "",
		"Agent-only. Comma-separated interface name prefixes to attach TC to.")
	flag.StringVar(&ifaceDeny, "tc-iface-deny", "",
		"Agent-only. Comma-separated interface name prefixes to exclude from TC attach.")
	flag.StringVar(&agentNamespace, "agent-namespace", "kubewol-system",
		"Controller-only. Namespace hosting the kubewol-agent headless Service.")
	flag.StringVar(&agentService, "agent-service", "kubewol-agent",
		"Controller-only. Name of the kubewol-agent headless Service.")
	flag.IntVar(&agentPort, "agent-port", 8444,
		"Controller-only. TCP port the agent exposes its gRPC service on.")
	flag.StringVar(&agentGRPCAddr, "agent-grpc-bind-address", ":8444",
		"Agent-only. gRPC service bind address. Serves the kubewol.v1.Agent "+
			"service over TLS with audience-bound TokenReview authentication.")
	flag.StringVar(&agentTLSCertFile, "agent-tls-cert-file", "",
		"Agent-only. Optional path to a PEM-encoded TLS certificate to serve on "+
			"the gRPC listener. When empty the agent mints a self-signed cert "+
			"in memory at startup.")
	flag.StringVar(&agentTLSKeyFile, "agent-tls-key-file", "",
		"Agent-only. Path to the PEM-encoded private key matching "+
			"--agent-tls-cert-file. Required when cert file is set.")
	flag.StringVar(&agentAllowedCallers, "agent-allowed-callers",
		"system:serviceaccount:kubewol-system:kubewol-controller",
		"Agent-only. Comma-separated list of user names that are permitted to "+
			"call the kubewol.v1.Agent service. Each entry must match a "+
			"TokenReview user.username exactly (typically "+
			"\"system:serviceaccount:<ns>:<sa>\"). The audience check alone is "+
			"not sufficient because any workload that can mint a projected "+
			"token for its own SA with audience kubewol.io/agent-api would "+
			"otherwise pass.")
	flag.StringVar(&agentTLSCAFile, "agent-tls-ca-file", "",
		"Controller-only. Path to a PEM CA bundle used to verify agent "+
			"certificates. If empty the controller dials agents with "+
			"InsecureSkipVerify (audience-bound token remains the primary "+
			"authentication gate). Populate this when you ship a shared CA, "+
			"for example via cert-manager.")
	flag.StringVar(&agentTLSServerName, "agent-tls-server-name", "",
		"Controller-only. Optional X.509 ServerName the agent certificate "+
			"must present. Requires --agent-tls-ca-file.")

	opts := zap.Options{Development: true}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	switch mode {
	case "agent":
		runAgent(probeAddr, metricsAddr, remoteWriteURL, ifaceAllow, ifaceDeny)
	case "controller":
		runController(probeAddr, metricsAddr, agentNamespace, agentService, agentPort,
			controller.FleetOptions{CAFile: agentTLSCAFile, ServerName: agentTLSServerName})
	default:
		setupLog.Error(nil, "unknown --mode", "mode", mode)
		os.Exit(1)
	}
}

// ─────────────────────────────────────────
// Agent entry point
// ─────────────────────────────────────────

func runAgent(probeAddr, metricsAddr, remoteWriteURL, ifaceAllow, ifaceDeny string) {
	predicate := buildInterfacePredicate(ifaceAllow, ifaceDeny)

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

	restConfig := ctrl.GetConfigOrDie()

	// Kubernetes client for the gRPC auth interceptor's audience-bound
	// TokenReview calls.
	k8s, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		setupLog.Error(err, "unable to build kubernetes client")
		os.Exit(1)
	}

	// Build the agent (BPF state owner + gRPC service target).
	ag := agent.New(bpfMgr, ctrl.Log.WithName("agent"))

	// controller-runtime manager: no reconcilers in agent mode; we only want
	// the secure /metrics server, the liveness probes, and the signal
	// plumbing. The agent API is served on a separate gRPC listener below.
	mgr, err := ctrl.NewManager(restConfig, ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress:    metricsAddr,
			SecureServing:  true,
			FilterProvider: metricsfilters.WithAuthenticationAndAuthorization,
		},
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         false,
	})
	if err != nil {
		setupLog.Error(err, "unable to start agent manager")
		os.Exit(1)
	}

	// readyzDown is set to the first fatal error observed by a background
	// goroutine (ring buffer reader, gRPC server). Once flipped, the
	// readyz probe starts returning that error so Kubernetes pulls the
	// pod out of the Service endpoints and its kubelet restarts it.
	// healthz stays healthy so the kubelet does not miss the transition.
	var readyzDown atomic.Pointer[error]

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", func(_ *http.Request) error {
		if p := readyzDown.Load(); p != nil {
			return *p
		}
		return nil
	}); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	// Expose BPF metrics via the shared registry.
	exporter := metrics.NewExporter(ag.ServiceMetrics, ag.DropCounts, remoteWriteURL)
	if err := exporter.Register(ctrlmetrics.Registry); err != nil {
		setupLog.Error(err, "unable to register eBPF exporter")
		os.Exit(1)
	}

	ctx := ctrl.SetupSignalHandler()

	markDown := func(err error) {
		// First writer wins.
		readyzDown.CompareAndSwap(nil, &err)
		setupLog.Error(err, "agent subsystem terminated; marking readyz unhealthy")
	}

	// Dynamic TC attach for veth pairs created after startup.
	go bpfMgr.WatchInterfaces(ctx, time.Second)

	// Ring buffer → gRPC SubscribeSynEvents stream fanout. Exit of this
	// goroutine means the direct-scale fast path is dead; flip readyz so
	// Kubernetes reschedules the pod instead of leaving it running silently.
	reader, err := newRingbufReader(bpfMgr.SynEventsMap())
	if err != nil {
		setupLog.Error(err, "failed to open ringbuf reader")
		os.Exit(1)
	}
	go func() {
		ag.RunRingBufReader(ctx, reader)
		if ctx.Err() == nil {
			markDown(errors.New("ring buffer reader exited unexpectedly"))
		}
	}()

	// Start the gRPC listener for the agent API on a separate port. If
	// --agent-tls-cert-file / --agent-tls-key-file are set (typical
	// cert-manager Certificate Secret mount), load them; otherwise fall
	// back to an in-memory self-signed cert — in which case controller
	// clients must use InsecureSkipVerify and lean on the audience-bound
	// token + caller identity pin for authentication.
	tlsCfg, err := agent.LoadTLSConfig(agentTLSCertFile, agentTLSKeyFile)
	if err != nil {
		setupLog.Error(err, "load agent TLS config",
			"cert", agentTLSCertFile, "key", agentTLSKeyFile)
		os.Exit(1)
	}
	// Parse the allowed caller list. Empty after trimming is a fatal
	// misconfiguration: the gate would otherwise accept any audience-bound
	// token, which is exactly the hole --agent-allowed-callers closes.
	allowed := splitPrefixes(agentAllowedCallers)
	if len(allowed) == 0 {
		setupLog.Error(nil, "--agent-allowed-callers must list at least one "+
			"ServiceAccount user name, e.g. "+
			"system:serviceaccount:kubewol-system:kubewol-controller")
		os.Exit(1)
	}
	grpcSrv := agent.NewGRPCServer(ag, k8s, tlsCfg, allowed)
	grpcListener, err := net.Listen("tcp", agentGRPCAddr)
	if err != nil {
		setupLog.Error(err, "gRPC listen", "addr", agentGRPCAddr)
		os.Exit(1)
	}
	go func() {
		setupLog.Info("starting agent gRPC server", "addr", agentGRPCAddr)
		if err := grpcSrv.Serve(grpcListener); err != nil && ctx.Err() == nil {
			markDown(fmt.Errorf("gRPC Serve: %w", err))
		}
	}()
	go func() {
		<-ctx.Done()
		grpcSrv.GracefulStop()
	}()

	setupLog.Info("starting agent manager")
	if err := mgr.Start(ctx); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

// ─────────────────────────────────────────
// Controller entry point
// ─────────────────────────────────────────

func runController(
	probeAddr, metricsAddr string,
	agentNamespace, agentService string,
	agentPort int,
	tls controller.FleetOptions,
) {
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress:    metricsAddr,
			SecureServing:  true,
			FilterProvider: metricsfilters.WithAuthenticationAndAuthorization,
		},
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         false,
	})
	if err != nil {
		setupLog.Error(err, "unable to start controller manager")
		os.Exit(1)
	}

	// Signal handler is set up here so the worker pool's context can be
	// tied to process shutdown. On SIGTERM the workers observe ctx.Done,
	// drain outstanding scaleCh sends, and exit cleanly.
	ctx := ctrl.SetupSignalHandler()

	// Placeholder reconciler: the Fleet is constructed before SetupWithManager
	// so the reconcile loop has a push target from the very first event. The
	// direct-scale handler is late-bound because it depends on the reconciler
	// itself, which we are building right now.
	reconciler := &controller.ScaleToZeroReconciler{
		Client:    mgr.GetClient(),
		APIReader: mgr.GetAPIReader(),
		Scheme:    mgr.GetScheme(),
	}

	// Bounded worker pool for direct-scale triggers. Each worker uses the
	// signal-handler context so a client-facing ctx cancel (caller of
	// TriggerScale) cannot abort the scale-subresource write mid-flight,
	// but process shutdown does stop new retries. The channel is closed on
	// ctx.Done() in a dedicated goroutine so range-loops unwind cleanly.
	scaleCh := make(chan scaleJob, 64)
	var workers sync.WaitGroup
	for i := 0; i < 4; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for job := range scaleCh {
				reconciler.TriggerScale(ctx, job.namespace, job.kind, job.name)
			}
		}()
	}
	go func() {
		<-ctx.Done()
		close(scaleCh)
	}()
	handleSyn := func(_ context.Context, evt *pb.SynEvent) {
		if evt == nil {
			return
		}
		// Use a non-blocking send against the shutdown context so a
		// late event after close(scaleCh) does not panic.
		defer func() {
			_ = recover()
		}()
		select {
		case <-ctx.Done():
			return
		case scaleCh <- scaleJob{
			namespace: evt.GetNamespace(),
			kind:      evt.GetTargetKind(),
			name:      evt.GetTargetName(),
		}:
		default:
			// Queue full — debounce already suppresses spam so drop is safe.
		}
	}

	fleet := controller.NewFleet(
		mgr.GetClient(),
		ctrl.Log.WithName("fleet"),
		agentNamespace, agentService, agentPort,
		handleSyn,
		tls,
	)
	reconciler.Fleet = fleet

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

	// Fleet.Run needs the manager's cache so it can subscribe to
	// EndpointSlice events via the informer already installed by the
	// reconciler. A small safety ticker inside Run also re-refreshes
	// every 60s to paper over any dropped event.
	go fleet.Run(ctx, mgr.GetCache())

	setupLog.Info("starting controller manager")
	if err := mgr.Start(ctx); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
	// Wait for the scale worker pool to drain before returning so late
	// TriggerScale calls do not get cut off mid K8s API write.
	workers.Wait()
}

// ─────────────────────────────────────────
// Shared helpers
// ─────────────────────────────────────────

// buildInterfacePredicate returns an interface filter for TC attach.
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

// scaleJob is enqueued to the bounded worker pool on every SubscribeSynEvents
// gRPC message received from any agent.
type scaleJob struct {
	namespace string
	kind      string
	name      string
}
