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

	pb "github.com/munenick/kubewol/internal/agentapi/pb"
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
	// It is configured on the Service only.
	//   kubectl annotate svc my-app kubewol/direct-scale=true
	AnnotationDirectScale = "kubewol/direct-scale"

	targetKindDeployment  = "Deployment"
	targetKindStatefulSet = "StatefulSet"

	annotationTrue = "true"

	// rstSuppressDelay keeps egress RST suppression ON after endpoints become ready
	// to cover kube-proxy iptables/ipvs rule propagation delay (typically <1s).
	rstSuppressDelay = 2 * time.Second

	// scaleDebounce is the minimum interval between direct-scale triggers for
	// the same target. Successful (and already-scaled) entries are retained so
	// a burst of SYN events cannot hammer the scale subresource. Failed entries
	// are cleared so retries are not suppressed indefinitely.
	scaleDebounce = 5 * time.Second

	// scaleInflightGC bounds scaleInflight growth; entries older than this are
	// pruned opportunistically on every TriggerScale call.
	scaleInflightGC = 10 * scaleDebounce
)

// WatchEntry tracks the desired BPF state for one Service port. Identical in
// shape to the agent API entry so marshalling is trivial.
type WatchEntry struct {
	Namespace   string
	Service     string
	TargetKind  string
	TargetName  string
	ClusterIP   net.IP
	Port        uint16
	NodePort    int32
	ProxyMode   bool
	DirectScale bool
	ReadySince  time.Time
}

// AgentFleet is the minimum interface the reconciler needs from the agent
// discovery + fanout subsystem. Implemented by controller.Fleet.
type AgentFleet interface {
	// PushAll sends the full desired watch state to every known agent in
	// parallel. Errors are aggregated but do not fail the reconcile — a
	// temporarily unreachable agent will catch up on the next reconcile.
	PushAll(ctx context.Context, spec *pb.WatchSpec) error
}

// ScaleToZeroReconciler reconciles Services annotated with kubewol/enabled=true.
// This controller owns the Kubernetes API side of kubewol. It never touches
// BPF; it pushes WatchSpec snapshots to the kubewol-agent DaemonSet via HTTP
// and receives SYN events back over the SubscribeSynEvents gRPC stream.
type ScaleToZeroReconciler struct {
	client.Client
	// APIReader is a non-cached client for one-off Deployment/StatefulSet lookups
	// and for the live direct-scale annotation check in TriggerScale.
	APIReader client.Reader
	Scheme    *runtime.Scheme
	Fleet     AgentFleet

	mu sync.RWMutex
	// watches is the per-Service desired state. Aggregated across all Services
	// to build the WatchSpec pushed to every agent.
	watches map[types.NamespacedName][]*WatchEntry

	// scaleInflight debounces direct-scale triggers per target.
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
// config/rbac/direct_scale_role.yaml and must be opted into explicitly.

// parsedService is the result of validating and extracting the kubewol-relevant
// fields from a Service.
type parsedService struct {
	ip         net.IP
	ports      []portSpec
	targetKind string
	targetName string
}

// parseService validates the Service annotations / spec and looks up the target
// workload kind. Returns (nil, nil) if the Service is disabled or unsupported.
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
	targetKind, err := r.detectTarget(ctx, svc.Namespace, targetName)
	if err != nil {
		return nil, err
	}

	ports := make([]portSpec, 0, len(svc.Spec.Ports))
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
		ip:         ip,
		ports:      ports,
		targetKind: targetKind,
		targetName: targetName,
	}, nil
}

// buildEntries constructs the desired per-port WatchEntry list for a Service,
// carrying forward readySince from the previous reconcile so rstSuppress has
// a stable time reference.
func (r *ScaleToZeroReconciler) buildEntries(svc *corev1.Service, ps *parsedService, ready int, directScale bool) ([]*WatchEntry, bool) {
	proxyMode := ready == 0
	name := client.ObjectKeyFromObject(svc)

	r.mu.RLock()
	prev := r.watches[name]
	r.mu.RUnlock()

	var readySince time.Time
	if len(prev) > 0 {
		readySince = prev[0].ReadySince
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
			Namespace:   svc.Namespace,
			Service:     svc.Name,
			TargetKind:  ps.targetKind,
			TargetName:  ps.targetName,
			ClusterIP:   ps.ip,
			Port:        p.port,
			NodePort:    p.nodePort,
			ProxyMode:   proxyMode,
			DirectScale: directScale,
			ReadySince:  readySince,
		})
	}
	return entries, rstSuppress
}

// pushFleet marshals the complete aggregated state and sends it to every
// agent. The reconcile keeps the in-memory view only if the push succeeds.
func (r *ScaleToZeroReconciler) pushFleet(ctx context.Context, name types.NamespacedName, entries []*WatchEntry, rstSuppress bool) error {
	r.mu.Lock()
	prev := r.watches[name]
	r.watches[name] = entries
	r.mu.Unlock()

	_ = rstSuppress // per-Service rstSuppress is recomputed per-entry in buildSpec
	spec := r.buildSpec()
	if err := r.Fleet.PushAll(ctx, spec); err != nil {
		// Roll the in-memory view back so the next reconcile retries cleanly.
		r.mu.Lock()
		if len(prev) == 0 {
			delete(r.watches, name)
		} else {
			r.watches[name] = prev
		}
		r.mu.Unlock()
		return err
	}
	return nil
}

// buildSpec snapshots the current watch map into a pb.WatchSpec the Fleet
// can send over gRPC. rstSuppress is recomputed per-entry against the
// current wall clock and each entry's ReadySince — no per-call parameter is
// needed because the reconciler holds the authoritative ReadySince on the
// WatchEntry itself.
func (r *ScaleToZeroReconciler) buildSpec() *pb.WatchSpec {
	r.mu.RLock()
	defer r.mu.RUnlock()
	now := time.Now()
	var out []*pb.WatchEntry
	for _, list := range r.watches {
		for _, e := range list {
			rst := e.ProxyMode || (!e.ReadySince.IsZero() && now.Sub(e.ReadySince) < rstSuppressDelay)
			out = append(out, &pb.WatchEntry{
				Namespace:   e.Namespace,
				Service:     e.Service,
				TargetKind:  e.TargetKind,
				TargetName:  e.TargetName,
				ClusterIp:   e.ClusterIP.String(),
				Port:        uint32(e.Port),
				NodePort:    e.NodePort,
				ProxyMode:   e.ProxyMode,
				RstSuppress: rst,
				DirectScale: e.DirectScale,
			})
		}
	}
	return &pb.WatchSpec{Watches: out}
}

func (r *ScaleToZeroReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var svc corev1.Service
	if err := r.Get(ctx, req.NamespacedName, &svc); err != nil {
		if errors.IsNotFound(err) {
			// Service was deleted. Propagate removeWatch failures so
			// controller-runtime requeues — otherwise a transient agent
			// outage at deletion time can leave stale BPF state on a
			// node indefinitely because there is no later reconcile
			// event for an object that no longer exists.
			if err := r.removeWatch(ctx, req.NamespacedName); err != nil {
				return ctrl.Result{}, fmt.Errorf("remove watch on delete: %w", err)
			}
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
		// Service still exists but is no longer kubewol-enabled. Same
		// propagation logic as the delete path above.
		if err := r.removeWatch(ctx, req.NamespacedName); err != nil {
			return ctrl.Result{}, fmt.Errorf("remove watch on disable: %w", err)
		}
		return ctrl.Result{}, nil
	}

	ready, err := r.countReadyEndpoints(ctx, svc.Namespace, svc.Name)
	if err != nil {
		logger.Error(err, "countReadyEndpoints failed; keeping proxy_mode ON")
		ready = 0
	}
	directScale := svc.Annotations[AnnotationDirectScale] == annotationTrue

	entries, rstSuppress := r.buildEntries(&svc, ps, ready, directScale)
	if err := r.pushFleet(ctx, req.NamespacedName, entries, rstSuppress); err != nil {
		return ctrl.Result{}, fmt.Errorf("push agent fleet: %w", err)
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

// detectTarget returns the kind (Deployment/StatefulSet) of the target workload.
func (r *ScaleToZeroReconciler) detectTarget(ctx context.Context, ns, name string) (string, error) {
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

type portSpec struct {
	port     uint16
	nodePort int32
}

// removeWatch drops the Service's entries from the in-memory view and pushes
// the updated spec to the fleet. On push failure the in-memory deletion is
// rolled back so the next reconcile retries against the same prev state —
// otherwise the controller's view would diverge from agent BPF state.
// Idempotent: no-op when the Service is not currently tracked.
func (r *ScaleToZeroReconciler) removeWatch(ctx context.Context, name types.NamespacedName) error {
	r.mu.Lock()
	prev, ok := r.watches[name]
	if !ok {
		r.mu.Unlock()
		return nil
	}
	delete(r.watches, name)
	r.mu.Unlock()

	if err := r.Fleet.PushAll(ctx, r.buildSpec()); err != nil {
		r.mu.Lock()
		// Only restore if a concurrent reconcile has not already written
		// a fresh entry for this key.
		if _, stillGone := r.watches[name]; !stillGone {
			r.watches[name] = prev
		}
		r.mu.Unlock()
		return err
	}
	return nil
}

// countReadyEndpoints returns the number of endpoints that are ready AND not terminating.
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

// TriggerScale patches the target workload's /scale subresource to 1 only if it
// is currently at 0. Debounced per target.
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

	newTarget := func() client.Object {
		switch kind {
		case targetKindStatefulSet:
			return &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}
		default:
			return &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}
		}
	}

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

// pruneInflightLocked drops scaleInflight entries older than scaleInflightGC.
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
