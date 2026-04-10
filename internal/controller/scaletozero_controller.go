/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv1 "k8s.io/api/autoscaling/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

	// AnnotationTargetName overrides the target workload name (default: same as Service name).
	// The kind (Deployment or StatefulSet) is auto-detected by Get lookup.
	//   kubectl annotate svc my-app kubewol/target-name=my-sts
	AnnotationTargetName = "kubewol/target-name"

	// AnnotationDirectScale enables eBPF-triggered direct scale 0->1 (fast path).
	// When enabled, kubewol patches the target's /scale subresource directly on
	// SYN detection, bypassing the HPA 15s sync period. ~1s cold start instead of ~19s.
	//   kubectl annotate svc my-app kubewol/direct-scale=true
	AnnotationDirectScale = "kubewol/direct-scale"

	targetKindDeployment  = "Deployment"
	targetKindStatefulSet = "StatefulSet"
)

// WatchEntry tracks BPF state for one Service.
type WatchEntry struct {
	Namespace   string
	Service     string
	TargetKind  string // "Deployment" or "StatefulSet"
	TargetName  string // workload name to scale
	ClusterIP   net.IP
	Port        uint16
	NodePort    int32
	BPFKey      bpf.SvcKey
	ProxyMode   bool
	DirectScale bool      // eBPF SYN triggers direct scale API call (fast path)
	ReadySince  time.Time // when endpoints first became ready (zero = not ready)
}

// ScaleToZeroReconciler reconciles Services annotated with kubewol/enabled=true.
type ScaleToZeroReconciler struct {
	client.Client
	// APIReader is a non-cached client for one-off Deployment/StatefulSet lookups
	// to avoid spinning up cluster-wide watches on these types.
	APIReader client.Reader
	Scheme    *runtime.Scheme
	BPF       *bpf.Manager

	mu      sync.RWMutex
	watches map[types.NamespacedName]*WatchEntry

	// scaleInflight debounces direct-scale triggers per deployment.
	scaleMu       sync.Mutex
	scaleInflight map[string]time.Time
}

// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch
// +kubebuilder:rbac:groups=discovery.k8s.io,resources=endpointslices,verbs=list;watch
// +kubebuilder:rbac:groups=apps,resources=deployments;statefulsets,verbs=get
// +kubebuilder:rbac:groups=apps,resources=deployments/scale,verbs=get;update;patch
// +kubebuilder:rbac:groups=apps,resources=statefulsets/scale,verbs=get;update;patch

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

	targetName := svc.Annotations[AnnotationTargetName]
	if targetName == "" {
		targetName = svc.Name
	}
	targetKind, err := r.detectTargetKind(ctx, svc.Namespace, targetName)
	if err != nil {
		logger.Error(err, "failed to detect target kind", "target", targetName)
		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
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
	proxyMode := ready == 0

	// proxy_mode (SYN DROP) toggles immediately.
	r.BPF.SetProxyMode(bpfKey, proxyMode, nodePort)

	// rst_suppress stays ON longer than proxy_mode to cover
	// kube-proxy iptables/ipvs propagation delay.
	// When proxy_mode turns OFF, SYN passes through. If DNAT isn't
	// ready yet, iptables REJECT sends RST. rst_suppress drops it.
	const rstSuppressDelay = 5 * time.Second

	r.mu.Lock()
	prev, exists := r.watches[req.NamespacedName]
	var readySince time.Time
	if exists {
		readySince = prev.ReadySince
	}
	if ready == 0 {
		readySince = time.Time{}
	} else if readySince.IsZero() {
		readySince = time.Now()
	}

	rstSuppress := ready == 0 || time.Since(readySince) < rstSuppressDelay
	r.BPF.SetRstSuppress(bpfKey, rstSuppress, nodePort)

	directScale := svc.Annotations[AnnotationDirectScale] == "true"

	r.watches[req.NamespacedName] = &WatchEntry{
		Namespace: svc.Namespace, Service: svc.Name,
		TargetKind: targetKind, TargetName: targetName,
		ClusterIP: ip, Port: port, NodePort: nodePort,
		BPFKey: bpfKey, ProxyMode: proxyMode,
		DirectScale: directScale, ReadySince: readySince,
	}
	r.mu.Unlock()

	logger.Info("reconciled",
		"service", svc.Name, "clusterIP", svc.Spec.ClusterIP,
		"port", port, "nodePort", nodePort,
		"target", targetKind+"/"+targetName,
		"proxyMode", proxyMode, "rstSuppress", rstSuppress,
		"directScale", directScale, "readyEndpoints", ready)

	// Requeue to disable rst_suppress after delay
	if rstSuppress && ready > 0 {
		return ctrl.Result{RequeueAfter: rstSuppressDelay}, nil
	}

	return ctrl.Result{}, nil
}

// detectTargetKind checks whether the target name is a Deployment or StatefulSet.
// Tries Deployment first, falls back to StatefulSet. Uses APIReader to bypass the
// controller-runtime cache (avoids cluster-wide watches on these types).
func (r *ScaleToZeroReconciler) detectTargetKind(ctx context.Context, ns, name string) (string, error) {
	key := client.ObjectKey{Namespace: ns, Name: name}
	reader := r.APIReader
	if reader == nil {
		reader = r.Client
	}

	var d appsv1.Deployment
	if err := reader.Get(ctx, key, &d); err == nil {
		return targetKindDeployment, nil
	} else if !errors.IsNotFound(err) {
		return "", err
	}

	var s appsv1.StatefulSet
	if err := reader.Get(ctx, key, &s); err == nil {
		return targetKindStatefulSet, nil
	} else if !errors.IsNotFound(err) {
		return "", err
	}

	return "", fmt.Errorf("no Deployment or StatefulSet named %q in namespace %q", name, ns)
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

// LookupByBPFKey finds a watch entry matching the BPF destination.
// Matches either ClusterIP:port or *:nodePort (for NodePort traffic).
// Returns nil if no match or if direct-scale is not enabled.
func (r *ScaleToZeroReconciler) LookupByBPFKey(dstAddr uint32, dstPort uint16) *WatchEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, e := range r.watches {
		clusterIPMatch := e.BPFKey.Addr == dstAddr && e.BPFKey.Port == dstPort
		nodePortMatch := e.NodePort > 0 && dstPort == bpf.Htons(uint16(e.NodePort))
		if clusterIPMatch || nodePortMatch {
			if !e.DirectScale {
				return nil
			}
			cp := *e
			return &cp
		}
	}
	return nil
}

// TriggerScale patches the target workload's /scale subresource from 0 to 1.
// Supports Deployment and StatefulSet. Debounced per target to avoid concurrent calls.
func (r *ScaleToZeroReconciler) TriggerScale(ctx context.Context, namespace, kind, name string) {
	key := namespace + "/" + kind + "/" + name

	r.scaleMu.Lock()
	if last, ok := r.scaleInflight[key]; ok && time.Since(last) < 30*time.Second {
		r.scaleMu.Unlock()
		return
	}
	if r.scaleInflight == nil {
		r.scaleInflight = make(map[string]time.Time)
	}
	r.scaleInflight[key] = time.Now()
	r.scaleMu.Unlock()

	logger := log.FromContext(ctx).WithName("direct-scale")
	start := time.Now()

	scale := &autoscalingv1.Scale{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec:       autoscalingv1.ScaleSpec{Replicas: 1},
	}

	var target client.Object
	switch kind {
	case targetKindStatefulSet:
		target = &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}
	default:
		target = &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}
	}

	if err := r.SubResource("scale").Update(ctx, target, client.WithSubResourceBody(scale)); err != nil {
		logger.Error(err, "scale 0->1 failed", "target", key)
		return
	}
	logger.Info("scaled 0->1", "target", key, "duration", time.Since(start))
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
