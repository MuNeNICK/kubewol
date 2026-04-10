/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

import (
	"context"
	"net"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	bpf "github.com/munenick/kubewol/internal/ebpf"
	"github.com/munenick/kubewol/internal/metrics"
)

const (
	// AnnotationEnabled marks a Service for kubewol monitoring.
	//   kubectl annotate svc my-app kubewol/enabled=true
	AnnotationEnabled = "kubewol/enabled"

	// AnnotationDeployment overrides the Deployment name (default: same as Service name).
	//   kubectl annotate svc my-app kubewol/deployment=my-deploy
	AnnotationDeployment = "kubewol/deployment"
)

// WatchEntry tracks BPF state for one Service.
type WatchEntry struct {
	Namespace    string
	Service      string
	Deployment   string
	ClusterIP    net.IP
	Port         uint16
	NodePort     int32
	BPFKey       bpf.SvcKey
	ProxyMode    bool
	ReadySince   time.Time // when endpoints first became ready (zero = not ready)
}

// ScaleToZeroReconciler reconciles Services annotated with kubewol/enabled=true.
type ScaleToZeroReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	BPF    *bpf.Manager

	mu      sync.RWMutex
	watches map[types.NamespacedName]*WatchEntry
}

// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch
// +kubebuilder:rbac:groups=discovery.k8s.io,resources=endpointslices,verbs=list;watch

func (r *ScaleToZeroReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var svc corev1.Service
	if err := r.Get(ctx, req.NamespacedName, &svc); err != nil {
		r.removeWatch(req.NamespacedName)
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if svc.Annotations[AnnotationEnabled] != "true" {
		r.removeWatch(req.NamespacedName)
		return ctrl.Result{}, nil
	}

	if svc.Spec.ClusterIP == "" || svc.Spec.ClusterIP == "None" {
		return ctrl.Result{}, nil
	}
	ip := net.ParseIP(svc.Spec.ClusterIP)
	if ip == nil {
		return ctrl.Result{}, nil
	}

	deployName := svc.Annotations[AnnotationDeployment]
	if deployName == "" {
		deployName = svc.Name
	}

	var port uint16
	var nodePort int32
	for _, p := range svc.Spec.Ports {
		if p.Protocol == corev1.ProtocolTCP || p.Protocol == "" {
			port = uint16(p.Port)
			nodePort = p.NodePort
			break
		}
	}
	if port == 0 {
		return ctrl.Result{}, nil
	}

	bpfKey, err := r.BPF.AddWatch(ip, port, nodePort)
	if err != nil {
		return ctrl.Result{}, err
	}

	ready := r.countReadyEndpoints(ctx, svc.Namespace, svc.Name)

	// Delay proxy_mode OFF by propagationDelay to let kube-proxy update iptables/ipvs.
	// Without this, a SYN retransmit can slip through before DNAT rules are ready,
	// causing iptables REJECT → RST → browser ERR_NETWORK_CHANGED.
	const propagationDelay = 5 * time.Second

	r.mu.Lock()
	prev, exists := r.watches[req.NamespacedName]
	var readySince time.Time
	if exists {
		readySince = prev.ReadySince
	}

	if ready == 0 {
		readySince = time.Time{} // reset
	} else if readySince.IsZero() {
		readySince = time.Now() // first ready
	}

	proxyMode := ready == 0 || time.Since(readySince) < propagationDelay
	r.BPF.SetProxyMode(bpfKey, proxyMode, nodePort)

	r.watches[req.NamespacedName] = &WatchEntry{
		Namespace: svc.Namespace, Service: svc.Name,
		Deployment: deployName, ClusterIP: ip, Port: port,
		NodePort: nodePort, BPFKey: bpfKey, ProxyMode: proxyMode,
		ReadySince: readySince,
	}
	r.mu.Unlock()

	logger.Info("reconciled",
		"service", svc.Name, "clusterIP", svc.Spec.ClusterIP,
		"port", port, "nodePort", nodePort,
		"proxyMode", proxyMode, "readyEndpoints", ready)

	// If we're in the propagation delay, requeue to turn off proxy_mode after the delay.
	if proxyMode && ready > 0 {
		return ctrl.Result{RequeueAfter: propagationDelay}, nil
	}

	return ctrl.Result{}, nil
}

func (r *ScaleToZeroReconciler) removeWatch(name types.NamespacedName) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.watches[name]; ok {
		r.BPF.RemoveWatch(e.ClusterIP, e.Port, e.NodePort)
		delete(r.watches, name)
	}
}

// countReadyEndpoints returns the number of endpoints that are ready AND not terminating.
// During scale-down, endpoints briefly appear as ready=false + terminating=true.
// We must not disable proxy_mode until there are stable, non-terminating ready endpoints.
func (r *ScaleToZeroReconciler) countReadyEndpoints(ctx context.Context, ns, svcName string) int {
	var list discoveryv1.EndpointSliceList
	if err := r.List(ctx, &list, client.InNamespace(ns),
		client.MatchingLabels{"kubernetes.io/service-name": svcName}); err != nil {
		return -1
	}
	n := 0
	for _, eps := range list.Items {
		for _, ep := range eps.Endpoints {
			ready := ep.Conditions.Ready != nil && *ep.Conditions.Ready
			terminating := ep.Conditions.Terminating != nil && *ep.Conditions.Terminating
			if ready && !terminating {
				n += len(ep.Addresses)
			}
		}
	}
	return n
}

// MetricsProvider returns the Provider for the Prometheus exporter.
// Returns cumulative BPF SYN counts. Prometheus computes rate()/increase().
func (r *ScaleToZeroReconciler) MetricsProvider() metrics.Provider {
	return func() []metrics.ServiceMetric {
		r.mu.RLock()
		defer r.mu.RUnlock()
		seen := map[string]bool{}
		var out []metrics.ServiceMetric
		for _, e := range r.watches {
			k := e.Namespace + "/" + e.Service
			if seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, metrics.ServiceMetric{
				Namespace: e.Namespace,
				Service:   e.Service,
				Count:     r.BPF.ReadSynCount(e.BPFKey),
			})
		}
		return out
	}
}

// SetupWithManager registers the controller.
func (r *ScaleToZeroReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.watches == nil {
		r.watches = make(map[types.NamespacedName]*WatchEntry)
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Service{}).
		Watches(&discoveryv1.EndpointSlice{},
			handler.EnqueueRequestsFromMapFunc(r.mapEndpointSlice)).
		Named("scaletozero").
		Complete(r)
}

func (r *ScaleToZeroReconciler) mapEndpointSlice(_ context.Context, obj client.Object) []reconcile.Request {
	svcName := obj.GetLabels()["kubernetes.io/service-name"]
	if svcName == "" {
		return nil
	}
	return []reconcile.Request{{
		NamespacedName: types.NamespacedName{
			Namespace: obj.GetNamespace(),
			Name:      svcName,
		},
	}}
}
