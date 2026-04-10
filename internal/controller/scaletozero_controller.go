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
	// to cover kube-proxy iptables/ipvs rule propagation delay (typically <1s).
	// Kept short to minimize the window where legitimate backend RSTs could be
	// over-suppressed; the eBPF egress filter additionally only drops payload-less
	// RSTs (kube-proxy REJECT pattern) so app-level resets carrying data still pass.
	rstSuppressDelay = 2 * time.Second

	// scaleDebounce is the minimum interval between direct-scale triggers for the same target.
	// Successful (and already-scaled) entries are retained so a burst of SYN events
	// cannot hammer the scale subresource. Failed entries are cleared so retries
	// are not suppressed indefinitely after a transient error.
	scaleDebounce = 5 * time.Second

	// scaleInflightGC bounds scaleInflight growth; entries older than this are
	// pruned opportunistically on every TriggerScale call.
	scaleInflightGC = 10 * scaleDebounce
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

	mu sync.RWMutex
	// watches indexes the per-Service WatchEntries. A Service with multiple TCP
	// ports yields multiple entries; they share Namespace/Service/TargetKind/
	// TargetName but each has its own Port/NodePort/BPFKey.
	watches map[types.NamespacedName][]*WatchEntry
	// bpfKeyIndex: O(1) reverse lookup from BPF SvcKey to WatchEntry. Used by the
	// direct-scale hot path so it does not have to scan the watches map.
	bpfKeyIndex map[bpf.SvcKey]*WatchEntry
	// nodePortIndex: O(1) reverse lookup from NodePort (network byte order, padded)
	// to WatchEntry, for NodePort traffic that hits the ring buffer.
	nodePortIndex map[uint32]*WatchEntry

	// scaleInflight debounces direct-scale triggers per target.
	// Entries are removed on success and on permanent failure so the map does not
	// grow unbounded; the timestamp window prevents back-to-back retries.
	scaleMu       sync.Mutex
	scaleInflight map[string]time.Time
}

// indexInsertLocked adds the entry to the reverse-lookup indexes. Caller holds r.mu.
func (r *ScaleToZeroReconciler) indexInsertLocked(e *WatchEntry) {
	if r.bpfKeyIndex == nil {
		r.bpfKeyIndex = make(map[bpf.SvcKey]*WatchEntry)
	}
	if r.nodePortIndex == nil {
		r.nodePortIndex = make(map[uint32]*WatchEntry)
	}
	r.bpfKeyIndex[e.BPFKey] = e
	if e.NodePort > 0 {
		r.nodePortIndex[uint32(bpf.Htons(uint16(e.NodePort)))] = e
	}
}

// indexRemoveLocked removes the entry from the reverse-lookup indexes ONLY if the
// indexed entry pointer still matches. This avoids removing a fresher entry that a
// concurrent reconcile installed under the same key. Caller holds r.mu.
func (r *ScaleToZeroReconciler) indexRemoveLocked(e *WatchEntry) {
	if cur, ok := r.bpfKeyIndex[e.BPFKey]; ok && cur == e {
		delete(r.bpfKeyIndex, e.BPFKey)
	}
	if e.NodePort > 0 {
		npKey := uint32(bpf.Htons(uint16(e.NodePort)))
		if cur, ok := r.nodePortIndex[npKey]; ok && cur == e {
			delete(r.nodePortIndex, npKey)
		}
	}
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

// parsedService is the result of validating and extracting the kubewol-relevant
// fields from a Service. Returned by parseService for the Reconcile loop.
type parsedService struct {
	ip             net.IP
	ports          []portSpec
	targetKind     string
	targetName     string
	directScaleOpt bool
}

// parseService validates the Service annotations / spec and looks up the target
// workload kind. Returns (nil, nil, nil) if the Service is disabled or unsupported,
// in which case the caller should remove any existing watch.
func (r *ScaleToZeroReconciler) parseService(ctx context.Context, svc *corev1.Service) (*parsedService, error) {
	logger := log.FromContext(ctx)

	if svc.Annotations[AnnotationEnabled] != annotationTrue {
		return nil, nil
	}
	if svc.Spec.ClusterIP == "" || svc.Spec.ClusterIP == "None" {
		return nil, nil
	}
	ip := net.ParseIP(svc.Spec.ClusterIP)
	if ip == nil || ip.To4() == nil {
		logger.Info("skipping non-IPv4 service", "clusterIP", svc.Spec.ClusterIP)
		return nil, nil
	}

	targetName := svc.Annotations[AnnotationTargetName]
	if targetName == "" {
		targetName = svc.Name
	}
	targetKind, directScaleOpt, err := r.detectTarget(ctx, svc.Namespace, targetName)
	if err != nil {
		return nil, err
	}

	var ports []portSpec
	for _, p := range svc.Spec.Ports {
		if p.Protocol != corev1.ProtocolTCP && p.Protocol != "" {
			continue
		}
		ports = append(ports, portSpec{port: uint16(p.Port), nodePort: p.NodePort})
	}
	if len(ports) == 0 {
		return nil, nil
	}

	return &parsedService{
		ip:             ip,
		ports:          ports,
		targetKind:     targetKind,
		targetName:     targetName,
		directScaleOpt: directScaleOpt,
	}, nil
}

// applyWatches programs BPF for the new desired state, then atomically swaps
// the in-memory index. On any BPF failure, the previous state (both BPF and
// in-memory) is restored so the controller view and the kernel maps stay
// consistent with whatever was working before.
//
// Order: BPF first (new), restore-on-failure, in-memory swap last. Reconcile
// for a single Service is single-threaded under controller-runtime, so no
// locking is needed between the BPF write phase and the swap phase.
func (r *ScaleToZeroReconciler) applyWatches(svc *corev1.Service, ps *parsedService, ready int, directScale bool) ([]*WatchEntry, bool, error) {
	proxyMode := ready == 0
	name := client.ObjectKeyFromObject(svc)

	// Snapshot the previous entries (shared reference; entries are not mutated
	// after publication so a slice copy is enough for rollback).
	r.mu.RLock()
	prevList := append([]*WatchEntry(nil), r.watches[name]...)
	r.mu.RUnlock()

	var readySince time.Time
	if len(prevList) > 0 {
		readySince = prevList[0].ReadySince
	}
	if ready == 0 {
		readySince = time.Time{}
	} else if readySince.IsZero() {
		readySince = time.Now()
	}
	rstSuppress := ready == 0 || time.Since(readySince) < rstSuppressDelay

	entries := make([]*WatchEntry, 0, len(ps.ports))
	for _, p := range ps.ports {
		entries = append(entries, &WatchEntry{
			Namespace: svc.Namespace, Service: svc.Name,
			TargetKind: ps.targetKind, TargetName: ps.targetName,
			ClusterIP: ps.ip, Port: p.port, NodePort: p.nodePort,
			BPFKey:      bpf.SvcKey{Addr: bpf.IPToUint32Must(ps.ip), Port: bpf.Htons(p.port)},
			ProxyMode:   proxyMode,
			DirectScale: directScale,
			ReadySince:  readySince,
		})
	}

	// Program BPF for the new entries. On first failure, revert BPF to the
	// snapshot of prevList so a transient map error does not wipe a healthy
	// working state.
	programmed := 0
	for i, e := range entries {
		if _, err := r.BPF.AddWatch(e.ClusterIP, e.Port, e.NodePort); err != nil {
			r.revertToPrev(entries[:i], prevList)
			return nil, false, fmt.Errorf("bpf AddWatch: %w", err)
		}
		if err := r.BPF.SetProxyMode(e.BPFKey, proxyMode, e.NodePort); err != nil {
			r.revertToPrev(entries[:i+1], prevList)
			return nil, false, fmt.Errorf("bpf SetProxyMode: %w", err)
		}
		if err := r.BPF.SetRstSuppress(e.BPFKey, rstSuppress, e.NodePort); err != nil {
			r.revertToPrev(entries[:i+1], prevList)
			return nil, false, fmt.Errorf("bpf SetRstSuppress: %w", err)
		}
		programmed = i + 1
	}
	_ = programmed // only used for clarity; all entries are programmed on success

	// BPF state is now the desired state. Swap the in-memory index.
	r.mu.Lock()
	for _, old := range prevList {
		r.indexRemoveLocked(old)
	}
	r.watches[name] = entries
	for _, e := range entries {
		r.indexInsertLocked(e)
	}
	r.mu.Unlock()

	return entries, rstSuppress, nil
}

// revertToPrev undoes a partial BPF apply and re-programs the previous entries
// so the kernel returns to the last known-good state. Best effort: errors in
// the revert path are logged but cannot be surfaced (the original error is the
// one the caller needs to see).
func (r *ScaleToZeroReconciler) revertToPrev(programmedNew []*WatchEntry, prev []*WatchEntry) {
	logger := log.Log.WithName("bpf-revert")
	// Tear down anything the new apply pushed.
	for _, e := range programmedNew {
		if err := r.BPF.RemoveWatch(e.ClusterIP, e.Port, e.NodePort); err != nil {
			logger.Error(err, "revert: RemoveWatch", "svc", e.Namespace+"/"+e.Service, "port", e.Port)
		}
	}
	// Re-program the snapshot so prev ports are back in the map.
	for _, e := range prev {
		if _, err := r.BPF.AddWatch(e.ClusterIP, e.Port, e.NodePort); err != nil {
			logger.Error(err, "revert: AddWatch", "svc", e.Namespace+"/"+e.Service, "port", e.Port)
			continue
		}
		if err := r.BPF.SetProxyMode(e.BPFKey, e.ProxyMode, e.NodePort); err != nil {
			logger.Error(err, "revert: SetProxyMode", "svc", e.Namespace+"/"+e.Service, "port", e.Port)
		}
		// rst_suppress is a time window; re-programming it as "enabled whenever
		// proxy_mode is on" is a safe superset of the original state.
		rstOn := e.ProxyMode || time.Since(e.ReadySince) < rstSuppressDelay
		if err := r.BPF.SetRstSuppress(e.BPFKey, rstOn, e.NodePort); err != nil {
			logger.Error(err, "revert: SetRstSuppress", "svc", e.Namespace+"/"+e.Service, "port", e.Port)
		}
	}
}

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

	ps, err := r.parseService(ctx, &svc)
	if err != nil {
		logger.Error(err, "parseService", "service", svc.Name)
		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	}
	if ps == nil {
		_ = r.removeWatch(req.NamespacedName)
		return ctrl.Result{}, nil
	}

	if err := r.cleanupStale(req.NamespacedName, ps.ip, ps.ports); err != nil {
		return ctrl.Result{}, fmt.Errorf("cleanup stale BPF state: %w", err)
	}

	ready, err := r.countReadyEndpoints(ctx, svc.Namespace, svc.Name)
	if err != nil {
		logger.Error(err, "countReadyEndpoints failed; keeping proxy_mode ON")
		ready = 0
	}
	directScale := svc.Annotations[AnnotationDirectScale] == annotationTrue && ps.directScaleOpt

	entries, rstSuppress, err := r.applyWatches(&svc, ps, ready, directScale)
	if err != nil {
		return ctrl.Result{}, err
	}

	logger.Info("reconciled",
		"service", svc.Name, "clusterIP", svc.Spec.ClusterIP,
		"ports", len(entries),
		"target", ps.targetKind+"/"+ps.targetName,
		"proxyMode", ready == 0, "rstSuppress", rstSuppress,
		"directScale", directScale,
		"readyEndpoints", ready)

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

// portSpec captures one Service TCP port (with optional NodePort).
type portSpec struct {
	port     uint16
	nodePort int32
}

// cleanupStale removes old BPF state for any port that no longer matches the new
// port set OR if the ClusterIP changed. Failure on any port returns an error so
// the reconcile is requeued instead of installing a new watch on top of stale state.
func (r *ScaleToZeroReconciler) cleanupStale(name types.NamespacedName, newIP net.IP, newPorts []portSpec) error {
	r.mu.RLock()
	prev := r.watches[name]
	r.mu.RUnlock()
	if len(prev) == 0 {
		return nil
	}

	// Build a set of (port,nodePort) pairs for the new spec.
	want := make(map[portSpec]struct{}, len(newPorts))
	for _, p := range newPorts {
		want[p] = struct{}{}
	}

	for _, e := range prev {
		// Same ClusterIP and same (port,nodePort) pair: still valid, leave it.
		if e.ClusterIP.Equal(newIP) {
			if _, ok := want[portSpec{port: e.Port, nodePort: e.NodePort}]; ok {
				continue
			}
		}
		// Stale: remove the BPF state.
		if err := r.BPF.RemoveWatch(e.ClusterIP, e.Port, e.NodePort); err != nil {
			return err
		}
		r.mu.Lock()
		r.indexRemoveLocked(e)
		r.mu.Unlock()
	}
	return nil
}

// removeWatch detaches BPF state for every port owned by this Service, then
// clears the in-memory entries only on success. Uses a pointer-equality check
// against the current map value so that a concurrent reconcile that installed
// a fresh entry list under the same NamespacedName is not erased.
func (r *ScaleToZeroReconciler) removeWatch(name types.NamespacedName) error {
	r.mu.RLock()
	entries, ok := r.watches[name]
	r.mu.RUnlock()
	if !ok || len(entries) == 0 {
		return nil
	}
	for _, e := range entries {
		if err := r.BPF.RemoveWatch(e.ClusterIP, e.Port, e.NodePort); err != nil {
			return err
		}
	}
	r.mu.Lock()
	if cur, ok := r.watches[name]; ok && len(cur) == len(entries) && cur[0] == entries[0] {
		delete(r.watches, name)
		for _, e := range entries {
			r.indexRemoveLocked(e)
		}
	}
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
// Returns cumulative BPF SYN counts (summed across all ports of a Service).
// Prometheus computes rate()/increase().
func (r *ScaleToZeroReconciler) MetricsProvider() metrics.Provider {
	logger := log.Log.WithName("metrics-provider")
	return func() []metrics.ServiceMetric {
		r.mu.RLock()
		defer r.mu.RUnlock()
		var out []metrics.ServiceMetric
		for _, entries := range r.watches {
			if len(entries) == 0 {
				continue
			}
			var total uint64
			for _, e := range entries {
				count, err := r.BPF.ReadSynCount(e.BPFKey)
				if err != nil {
					logger.Error(err, "read syn_count",
						"service", e.Namespace+"/"+e.Service, "port", e.Port)
					continue
				}
				total += count
			}
			head := entries[0]
			out = append(out, metrics.ServiceMetric{
				Namespace: head.Namespace,
				Service:   head.Service,
				Count:     total,
			})
		}
		return out
	}
}

// LookupByBPFKey finds a watch entry matching the BPF destination via O(1)
// reverse-index lookup. Matches either ClusterIP:port or *:nodePort
// (for NodePort traffic). Returns nil if no match or if direct-scale is not enabled.
func (r *ScaleToZeroReconciler) LookupByBPFKey(dstAddr uint32, dstPort uint16) *WatchEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// ClusterIP-keyed lookup.
	if e, ok := r.bpfKeyIndex[bpf.SvcKey{Addr: dstAddr, Port: dstPort}]; ok {
		if !e.DirectScale {
			return nil
		}
		cp := *e
		return &cp
	}
	// NodePort-keyed lookup (port-only).
	if e, ok := r.nodePortIndex[uint32(dstPort)]; ok {
		if !e.DirectScale {
			return nil
		}
		cp := *e
		return &cp
	}
	return nil
}

// TriggerScale patches the target workload's /scale subresource to 1 ONLY if it is
// currently at 0 replicas. Debounced per target.
//
// The target's kubewol/direct-scale annotation is re-checked against a non-cached
// API read immediately before the patch: the Service-level annotation snapshot is
// captured at reconcile time and is not sufficient as a live safety gate — a user
// who has just removed the annotation from the workload must see fast-path scaling
// stop immediately, not at the next Service/EndpointSlice event.
func (r *ScaleToZeroReconciler) TriggerScale(ctx context.Context, namespace, kind, name string) {
	key := namespace + "/" + kind + "/" + name

	r.scaleMu.Lock()
	if r.scaleInflight == nil {
		r.scaleInflight = make(map[string]time.Time)
	}
	r.pruneInflightLocked()
	if last, ok := r.scaleInflight[key]; ok && time.Since(last) < scaleDebounce {
		r.scaleMu.Unlock()
		return
	}
	r.scaleInflight[key] = time.Now()
	r.scaleMu.Unlock()

	logger := log.FromContext(ctx).WithName("direct-scale")
	start := time.Now()

	// Live annotation re-check. Uses APIReader (non-cached) so a just-removed
	// annotation is observed immediately; the reconcile cache may lag.
	if !r.isDirectScaleAllowed(ctx, namespace, kind, name) {
		logger.V(1).Info("direct-scale denied by live annotation check", "target", key)
		r.clearInflight(key)
		return
	}

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
	// Success path: keep the timestamp so subsequent SYN bursts within scaleDebounce
	// are suppressed. Stale entries are pruned opportunistically at the top of
	// TriggerScale so the map cannot grow without bound.
	if alreadyScaled {
		logger.V(1).Info("skipping direct-scale; already scaled", "target", key)
		return
	}
	logger.Info("scaled 0->1", "target", key, "duration", time.Since(start))
}

// isDirectScaleAllowed re-reads the target workload via the non-cached API reader
// and returns true only if the kubewol/direct-scale annotation is still "true".
// This is the live opt-out gate: removing the annotation from the Deployment or
// StatefulSet takes effect on the very next SYN event, not at the next reconcile.
func (r *ScaleToZeroReconciler) isDirectScaleAllowed(ctx context.Context, namespace, kind, name string) bool {
	reader := r.APIReader
	if reader == nil {
		reader = r.Client
	}
	k := client.ObjectKey{Namespace: namespace, Name: name}
	switch kind {
	case targetKindStatefulSet:
		var s appsv1.StatefulSet
		if err := reader.Get(ctx, k, &s); err != nil {
			return false
		}
		return s.Annotations[AnnotationDirectScale] == annotationTrue
	default:
		var d appsv1.Deployment
		if err := reader.Get(ctx, k, &d); err != nil {
			return false
		}
		return d.Annotations[AnnotationDirectScale] == annotationTrue
	}
}

// pruneInflightLocked drops scaleInflight entries older than scaleInflightGC.
// Caller holds scaleMu.
func (r *ScaleToZeroReconciler) pruneInflightLocked() {
	cutoff := time.Now().Add(-scaleInflightGC)
	for k, t := range r.scaleInflight {
		if t.Before(cutoff) {
			delete(r.scaleInflight, k)
		}
	}
}

func (r *ScaleToZeroReconciler) clearInflight(key string) {
	r.scaleMu.Lock()
	delete(r.scaleInflight, key)
	r.scaleMu.Unlock()
}

// SetupWithManager registers the controller.
func (r *ScaleToZeroReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.watches == nil {
		r.watches = make(map[types.NamespacedName][]*WatchEntry)
	}
	if r.bpfKeyIndex == nil {
		r.bpfKeyIndex = make(map[bpf.SvcKey]*WatchEntry)
	}
	if r.nodePortIndex == nil {
		r.nodePortIndex = make(map[uint32]*WatchEntry)
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
