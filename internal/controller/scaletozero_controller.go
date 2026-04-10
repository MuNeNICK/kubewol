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
	"k8s.io/client-go/util/retry"
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
	// Must be set on BOTH the Service AND the target workload (Deployment/StatefulSet).
	// Requiring the annotation on the target prevents privilege escalation: a user who
	// can only mutate Services cannot redirect kubewol to patch arbitrary workloads.
	//   kubectl annotate svc my-app kubewol/direct-scale=true
	//   kubectl annotate deploy my-app kubewol/direct-scale=true
	AnnotationDirectScale = "kubewol/direct-scale"

	targetKindDeployment  = "Deployment"
	targetKindStatefulSet = "StatefulSet"

	annotationTrue = "true"

	// rstSuppressDelay keeps egress RST suppression ON after endpoints become ready
	// to cover kube-proxy iptables/ipvs rule propagation delay.
	rstSuppressDelay = 5 * time.Second

	// scaleDebounce is the minimum interval between direct-scale triggers for the same target.
	// Cleared on failure so that retries are not suppressed indefinitely.
	scaleDebounce = 5 * time.Second
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

	// scaleInflight debounces direct-scale triggers per target.
	// Cleared on both success and failure so retries are not suppressed.
	scaleMu       sync.Mutex
	scaleInflight map[string]time.Time
}

// Required for observation (always installed):
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch
// +kubebuilder:rbac:groups=discovery.k8s.io,resources=endpointslices,verbs=list;watch
// +kubebuilder:rbac:groups=apps,resources=deployments;statefulsets,verbs=get
//
// NOTE: direct-scale write permissions (deployments/scale, statefulsets/scale
// with verbs get;update;patch) are NOT declared here. They live in
// config/rbac/direct_scale_role.yaml and must be opted into explicitly because
// cluster-wide write on scale subresources is a powerful privilege. Without this
// role applied, TriggerScale calls will fail with a forbidden error and the
// controller falls back to HPA-only behavior.

func (r *ScaleToZeroReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var svc corev1.Service
	if err := r.Get(ctx, req.NamespacedName, &svc); err != nil {
		if errors.IsNotFound(err) {
			_ = r.removeWatch(req.NamespacedName)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	if svc.Annotations[AnnotationEnabled] != annotationTrue {
		if err := r.removeWatch(req.NamespacedName); err != nil {
			logger.Error(err, "cleanup BPF state for disabled service")
		}
		return ctrl.Result{}, nil
	}

	if svc.Spec.ClusterIP == "" || svc.Spec.ClusterIP == "None" {
		return ctrl.Result{}, nil
	}
	ip := net.ParseIP(svc.Spec.ClusterIP)
	if ip == nil || ip.To4() == nil {
		// IPv6/dual-stack not supported yet (TC programs parse IPv4 only).
		logger.Info("skipping non-IPv4 service", "clusterIP", svc.Spec.ClusterIP)
		return ctrl.Result{}, nil
	}

	targetName := svc.Annotations[AnnotationTargetName]
	if targetName == "" {
		targetName = svc.Name
	}
	targetKind, directScaleOpt, err := r.detectTarget(ctx, svc.Namespace, targetName)
	if err != nil {
		logger.Error(err, "failed to detect target", "target", targetName)
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

	// If the previous watch had a different key (Service port/ClusterIP/NodePort changed),
	// remove the stale BPF entries before installing the new one.
	if err := r.cleanupStale(req.NamespacedName, ip, port, nodePort); err != nil {
		logger.Error(err, "cleanup stale BPF state")
	}

	// Fail-closed: if we cannot determine endpoint state, keep proxy_mode ON.
	ready, err := r.countReadyEndpoints(ctx, svc.Namespace, svc.Name)
	if err != nil {
		logger.Error(err, "countReadyEndpoints failed; keeping proxy_mode ON")
		ready = 0
	}
	proxyMode := ready == 0

	// Compute ReadySince and the fully-populated WatchEntry BEFORE enabling any BPF state.
	// This guarantees that by the time the TC ingress starts dropping SYNs and emitting
	// ring buffer events, LookupByBPFKey can already resolve the entry for direct-scale.
	bpfKey := bpf.SvcKey{Addr: bpf.IPToUint32Must(ip), Port: bpf.Htons(port)}
	directScale := svc.Annotations[AnnotationDirectScale] == annotationTrue && directScaleOpt

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

	entry := &WatchEntry{
		Namespace: svc.Namespace, Service: svc.Name,
		TargetKind: targetKind, TargetName: targetName,
		ClusterIP: ip, Port: port, NodePort: nodePort,
		BPFKey: bpfKey, ProxyMode: proxyMode,
		DirectScale: directScale,
		ReadySince:  readySince,
	}
	r.watches[req.NamespacedName] = entry
	r.mu.Unlock()

	// Now enable BPF state. Order is ingress-first (counts & notifies) then proxy_mode
	// (enables DROP+ring buffer), then egress RST suppression.
	if _, err := r.BPF.AddWatch(ip, port, nodePort); err != nil {
		// Roll back the in-memory entry so stale state doesn't accumulate.
		r.mu.Lock()
		delete(r.watches, req.NamespacedName)
		r.mu.Unlock()
		return ctrl.Result{}, fmt.Errorf("bpf AddWatch: %w", err)
	}
	if err := r.BPF.SetProxyMode(bpfKey, proxyMode, nodePort); err != nil {
		return ctrl.Result{}, fmt.Errorf("bpf SetProxyMode: %w", err)
	}
	if err := r.BPF.SetRstSuppress(bpfKey, rstSuppress, nodePort); err != nil {
		return ctrl.Result{}, fmt.Errorf("bpf SetRstSuppress: %w", err)
	}

	logger.Info("reconciled",
		"service", svc.Name, "clusterIP", svc.Spec.ClusterIP,
		"port", port, "nodePort", nodePort,
		"target", targetKind+"/"+targetName,
		"proxyMode", proxyMode, "rstSuppress", rstSuppress,
		"directScale", directScale,
		"readyEndpoints", ready)

	// Requeue to disable rst_suppress after delay
	if rstSuppress && ready > 0 {
		return ctrl.Result{RequeueAfter: rstSuppressDelay}, nil
	}

	return ctrl.Result{}, nil
}

// detectTarget returns the kind (Deployment/StatefulSet) of the target workload
// and whether the target itself opts into direct-scale via annotation.
// Requiring the annotation on the target prevents annotation-based privilege escalation
// from the Service side.
func (r *ScaleToZeroReconciler) detectTarget(ctx context.Context, ns, name string) (string, bool, error) {
	key := client.ObjectKey{Namespace: ns, Name: name}
	reader := r.APIReader
	if reader == nil {
		reader = r.Client
	}

	var d appsv1.Deployment
	if err := reader.Get(ctx, key, &d); err == nil {
		return targetKindDeployment, d.Annotations[AnnotationDirectScale] == annotationTrue, nil
	} else if !errors.IsNotFound(err) {
		return "", false, err
	}

	var s appsv1.StatefulSet
	if err := reader.Get(ctx, key, &s); err == nil {
		return targetKindStatefulSet, s.Annotations[AnnotationDirectScale] == annotationTrue, nil
	} else if !errors.IsNotFound(err) {
		return "", false, err
	}

	return "", false, fmt.Errorf("no Deployment or StatefulSet named %q in namespace %q", name, ns)
}

// cleanupStale removes old BPF state if the Service key (ClusterIP/port/NodePort)
// changed between reconciles. Without this, port/nodePort changes leave dangling
// BPF entries that can silently drop traffic forever.
func (r *ScaleToZeroReconciler) cleanupStale(name types.NamespacedName, newIP net.IP, newPort uint16, newNodePort int32) error {
	r.mu.RLock()
	prev, exists := r.watches[name]
	r.mu.RUnlock()
	if !exists {
		return nil
	}
	if prev.ClusterIP.Equal(newIP) && prev.Port == newPort && prev.NodePort == newNodePort {
		return nil
	}
	return r.BPF.RemoveWatch(prev.ClusterIP, prev.Port, prev.NodePort)
}

// removeWatch detaches BPF state first, then clears the in-memory entry only
// on success. If BPF cleanup fails, the entry is preserved so that a subsequent
// reconcile can retry, and direct-scale / metrics lookups still resolve the target.
func (r *ScaleToZeroReconciler) removeWatch(name types.NamespacedName) error {
	r.mu.RLock()
	entry, ok := r.watches[name]
	r.mu.RUnlock()
	if !ok {
		return nil
	}
	if err := r.BPF.RemoveWatch(entry.ClusterIP, entry.Port, entry.NodePort); err != nil {
		return err
	}
	r.mu.Lock()
	delete(r.watches, name)
	r.mu.Unlock()
	return nil
}

// countReadyEndpoints returns the number of endpoints that are ready AND not terminating.
// Returns an error on list failure so the reconciler can fail-closed (keep proxy_mode ON)
// during transient API/cache issues.
func (r *ScaleToZeroReconciler) countReadyEndpoints(ctx context.Context, ns, svcName string) (int, error) {
	var list discoveryv1.EndpointSliceList
	if err := r.List(ctx, &list, client.InNamespace(ns),
		client.MatchingLabels{"kubernetes.io/service-name": svcName}); err != nil {
		return 0, fmt.Errorf("list endpointslices: %w", err)
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
	return n, nil
}

// MetricsProvider returns the Provider for the Prometheus exporter.
// Returns cumulative BPF SYN counts. Prometheus computes rate()/increase().
func (r *ScaleToZeroReconciler) MetricsProvider() metrics.Provider {
	logger := log.Log.WithName("metrics-provider")
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
			count, err := r.BPF.ReadSynCount(e.BPFKey)
			if err != nil {
				logger.Error(err, "read syn_count", "key", k)
				continue
			}
			out = append(out, metrics.ServiceMetric{
				Namespace: e.Namespace,
				Service:   e.Service,
				Count:     count,
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

// TriggerScale patches the target workload's /scale subresource to 1 ONLY if it is
// currently at 0 replicas. This prevents clobbering HPA or manual scale-up decisions.
// Debounced per target. The debounce entry is cleared on both success and failure so
// that retries are not suppressed indefinitely after a transient error.
func (r *ScaleToZeroReconciler) TriggerScale(ctx context.Context, namespace, kind, name string) {
	key := namespace + "/" + kind + "/" + name

	r.scaleMu.Lock()
	if r.scaleInflight == nil {
		r.scaleInflight = make(map[string]time.Time)
	}
	if last, ok := r.scaleInflight[key]; ok && time.Since(last) < scaleDebounce {
		r.scaleMu.Unlock()
		return
	}
	r.scaleInflight[key] = time.Now()
	r.scaleMu.Unlock()

	logger := log.FromContext(ctx).WithName("direct-scale")
	start := time.Now()

	newTarget := func() client.Object {
		switch kind {
		case targetKindStatefulSet:
			return &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}
		default:
			return &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}
		}
	}

	// Retry on Conflict so that cross-node races from multiple DaemonSet pods
	// or concurrent HPA updates do not fail; re-read scale and re-check replicas==0.
	alreadyScaled := false
	err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		target := newTarget()
		scale := &autoscalingv1.Scale{}
		if err := r.SubResource("scale").Get(ctx, target, scale); err != nil {
			return err
		}
		if scale.Spec.Replicas != 0 {
			alreadyScaled = true
			return nil
		}
		scale.Spec.Replicas = 1
		return r.SubResource("scale").Update(ctx, target, client.WithSubResourceBody(scale))
	})

	if err != nil {
		logger.Error(err, "direct-scale failed", "target", key)
		r.clearInflight(key)
		return
	}
	if alreadyScaled {
		logger.V(1).Info("skipping direct-scale; already scaled", "target", key)
		return
	}
	logger.Info("scaled 0->1", "target", key, "duration", time.Since(start))
}

func (r *ScaleToZeroReconciler) clearInflight(key string) {
	r.scaleMu.Lock()
	delete(r.scaleInflight, key)
	r.scaleMu.Unlock()
}

// SetupWithManager registers the controller.
func (r *ScaleToZeroReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.watches == nil {
		r.watches = make(map[types.NamespacedName]*WatchEntry)
	}
	if r.scaleInflight == nil {
		r.scaleInflight = make(map[string]time.Time)
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
