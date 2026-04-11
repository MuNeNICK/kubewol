package controller

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/go-logr/logr"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/client-go/tools/cache"
	ctrlcache "sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/munenick/kubewol/internal/agentapi"
	pb "github.com/munenick/kubewol/internal/agentapi/pb"
)

// SynEventHandler is invoked for every gRPC stream event received from any agent.
type SynEventHandler func(ctx context.Context, evt *pb.SynEvent)

// FleetOptions tunes the Fleet's TLS and token sourcing for per-agent
// gRPC connections. Mirrors agentapi.ClientOptions but omits TokenPath
// because the token path is a process-wide concern owned by main.go.
type FleetOptions struct {
	CAFile     string
	ServerName string
}

// Fleet maintains the set of kubewol-agent pods reachable over gRPC. It
// subscribes to EndpointSlices for the agent headless Service via the
// controller-runtime informer, keeps a per-pod bidirectional stream open
// for direct-scale SYN events, fans the current WatchSpec out to every
// reachable agent on PushAll, and backfills new agents with the last
// pushed snapshot at discovery time so pod restarts converge without
// waiting for the next reconcile.
//
// It implements the AgentFleet interface the reconciler expects.
type Fleet struct {
	k8s        client.Client
	logger     logr.Logger
	namespace  string
	serviceKey string // "kubewol-agent" — matches EndpointSlice label
	port       int    // agent gRPC port
	onEvent    SynEventHandler
	tls        FleetOptions

	mu      sync.Mutex
	clients map[string]*agentClient // keyed by "ip:port"
	// lastSpec is the most recent spec PushAll was asked to distribute.
	// New agents discovered in refresh() receive this snapshot immediately
	// so a restarted DaemonSet pod rebuilds its BPF state without having
	// to wait for the next Service/EndpointSlice reconcile event.
	lastSpec *pb.WatchSpec
}

type agentClient struct {
	target string // host:port
	client *agentapi.Client
	cancel context.CancelFunc
}

// NewFleet constructs a Fleet. namespace is the namespace the agent DaemonSet
// runs in; serviceKey is the headless Service name; port is the agent gRPC
// port (typically 8444); tls configures optional peer verification.
func NewFleet(k8s client.Client, logger logr.Logger, namespace, serviceKey string, port int, onEvent SynEventHandler, tls FleetOptions) *Fleet {
	return &Fleet{
		k8s:        k8s,
		logger:     logger.WithName("fleet"),
		namespace:  namespace,
		serviceKey: serviceKey,
		port:       port,
		onEvent:    onEvent,
		tls:        tls,
		clients:    map[string]*agentClient{},
	}
}

// Run blocks until ctx is cancelled. It subscribes to EndpointSlice events
// via the controller-runtime cache (informer) and refreshes its per-pod
// client set whenever a slice for the agent headless Service changes. A
// periodic safety net also re-refreshes every 60 seconds in case an event
// is missed.
//
// When the cache is nil the Fleet falls back to polling the API every 5
// seconds — that path is only reached by main.go in agent mode where no
// reconcile manager exists.
func (f *Fleet) Run(ctx context.Context, mgrCache ctrlcache.Cache) {
	if mgrCache == nil {
		f.runPoll(ctx, 5*time.Second)
		return
	}

	// Install an event handler on the EndpointSlice informer scoped to the
	// kubewol-agent Service. Every Add/Update/Delete triggers refresh(),
	// which rebuilds the per-pod gRPC client set and opens/closes streams.
	informer, err := mgrCache.GetInformer(ctx, &discoveryv1.EndpointSlice{})
	if err != nil {
		f.logger.Error(err, "failed to obtain EndpointSlice informer; falling back to polling")
		f.runPoll(ctx, 5*time.Second)
		return
	}
	refresh := func(_ interface{}) {
		if err := f.refresh(ctx); err != nil {
			f.logger.V(1).Info("agent refresh failed", "error", err.Error())
		}
	}
	_, err = informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    refresh,
		UpdateFunc: func(_, obj interface{}) { refresh(obj) },
		DeleteFunc: refresh,
	})
	if err != nil {
		f.logger.Error(err, "failed to register EndpointSlice handler; falling back to polling")
		f.runPoll(ctx, 5*time.Second)
		return
	}

	// Initial refresh: the cache may or may not be synced yet, so the first
	// call is best-effort and the ticker fills any gaps until the informer
	// delivers the first event.
	_ = f.refresh(ctx)

	safety := time.NewTicker(60 * time.Second)
	defer safety.Stop()
	for {
		select {
		case <-ctx.Done():
			f.closeAll()
			return
		case <-safety.C:
			_ = f.refresh(ctx)
		}
	}
}

// runPoll is the fallback discovery loop for environments where no cache is
// available (unit tests, misconfigured managers). Preserved to keep the
// controller-runtime cache path a pure optimization.
func (f *Fleet) runPoll(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	_ = f.refresh(ctx)
	for {
		select {
		case <-ctx.Done():
			f.closeAll()
			return
		case <-ticker.C:
			if err := f.refresh(ctx); err != nil {
				f.logger.V(1).Info("agent refresh failed", "error", err.Error())
			}
		}
	}
}

// refresh lists EndpointSlices for the agent Service and synchronises the
// per-pod client set against the observed IPs.
func (f *Fleet) refresh(ctx context.Context) error {
	var list discoveryv1.EndpointSliceList
	if err := f.k8s.List(ctx, &list,
		client.InNamespace(f.namespace),
		client.MatchingLabels{"kubernetes.io/service-name": f.serviceKey},
	); err != nil {
		return fmt.Errorf("list EndpointSlices: %w", err)
	}

	seen := map[string]struct{}{}
	for _, slice := range list.Items {
		for _, ep := range slice.Endpoints {
			if ep.Conditions.Ready != nil && !*ep.Conditions.Ready {
				continue
			}
			for _, addr := range ep.Addresses {
				if net.ParseIP(addr) == nil {
					continue
				}
				key := net.JoinHostPort(addr, strconv.Itoa(f.port))
				seen[key] = struct{}{}
			}
		}
	}

	f.mu.Lock()
	// Collect newly-added clients while still holding the lock so we can
	// backfill them with lastSpec once the lock is released.
	fresh := make([]*agentClient, 0, len(seen))
	for key := range seen {
		if _, ok := f.clients[key]; ok {
			continue
		}
		c, err := agentapi.NewClientWithOptions(key, agentapi.ClientOptions{
			CAFile:     f.tls.CAFile,
			ServerName: f.tls.ServerName,
		})
		if err != nil {
			f.logger.Error(err, "new agent client", "target", key)
			continue
		}
		subCtx, cancel := context.WithCancel(context.Background())
		ac := &agentClient{target: key, client: c, cancel: cancel}
		f.clients[key] = ac
		fresh = append(fresh, ac)
		go f.runSubscription(subCtx, ac)
		f.logger.Info("agent registered", "target", key)
	}
	// Drop stale clients (pods removed or moved).
	for key, ac := range f.clients {
		if _, ok := seen[key]; ok {
			continue
		}
		ac.cancel()
		_ = ac.client.Close()
		delete(f.clients, key)
		f.logger.Info("agent dropped", "target", ac.target)
	}
	snapshot := f.lastSpec
	f.mu.Unlock()

	// Backfill any brand-new agents with the most recent WatchSpec so a
	// restarted DaemonSet pod does not sit with empty BPF state until the
	// next Service / EndpointSlice reconcile. Best-effort; failures are
	// logged and the next reconcile will retry.
	if snapshot != nil && len(fresh) > 0 {
		for _, ac := range fresh {
			go func(ac *agentClient) {
				cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
				defer cancel()
				if err := ac.client.PutWatches(cctx, snapshot); err != nil {
					f.logger.V(1).Info("backfill push failed",
						"agent", ac.target, "error", err.Error())
				}
			}(ac)
		}
	}
	return nil
}

// runSubscription opens a SubscribeSynEvents gRPC stream and reconnects with
// backoff until the client's context is cancelled by refresh().
func (f *Fleet) runSubscription(ctx context.Context, ac *agentClient) {
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		err := ac.client.StreamSynEvents(ctx, func(evt *pb.SynEvent) {
			if f.onEvent != nil {
				f.onEvent(ctx, evt)
			}
		})
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			f.logger.V(1).Info("syn event stream disconnected",
				"agent", ac.target, "error", err.Error())
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < 10*time.Second {
			backoff *= 2
		}
	}
}

// PushAll fans the given WatchSpec out to every known agent in parallel and
// returns an aggregated error describing every failure. The caller
// (ScaleToZeroReconciler) is expected to requeue the reconcile on any
// non-nil error so a transient agent outage does not leave the fleet in a
// partially-applied state.
//
// "No agents yet" is reported as a nil error, not a failure: the reconciler
// would otherwise hot-loop during controller startup before the EndpointSlice
// informer has delivered the first agent. Once at least one agent exists the
// lastSpec cache in refresh() ensures it converges on the next reconcile.
func (f *Fleet) PushAll(ctx context.Context, spec *pb.WatchSpec) error {
	f.mu.Lock()
	targets := make([]*agentClient, 0, len(f.clients))
	for _, ac := range f.clients {
		targets = append(targets, ac)
	}
	f.mu.Unlock()

	if len(targets) == 0 {
		f.logger.V(1).Info("PushAll: no agents yet")
		// No agents to push to, but the caller asked for this spec so
		// cache it — the next agent that joins should converge on it.
		f.mu.Lock()
		f.lastSpec = spec
		f.mu.Unlock()
		return nil
	}

	var wg sync.WaitGroup
	errCh := make(chan error, len(targets))
	for _, ac := range targets {
		wg.Add(1)
		go func(ac *agentClient) {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			if err := ac.client.PutWatches(cctx, spec); err != nil {
				f.logger.V(1).Info("PutWatches failed",
					"agent", ac.target, "error", err.Error())
				errCh <- fmt.Errorf("%s: %w", ac.target, err)
			}
		}(ac)
	}
	wg.Wait()
	close(errCh)
	errs := make([]error, 0, len(targets))
	for err := range errCh {
		errs = append(errs, err)
	}
	// Only cache the spec when it was delivered to every agent we know
	// about. On partial failure the reconciler rolls back r.watches and
	// will push a different (previous) spec on retry — if we updated
	// lastSpec here a newly-discovered agent would be backfilled with
	// the failed spec and diverge from everyone else.
	if len(errs) == 0 {
		f.mu.Lock()
		f.lastSpec = spec
		f.mu.Unlock()
	}
	return errors.Join(errs...)
}

func (f *Fleet) closeAll() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, ac := range f.clients {
		ac.cancel()
		_ = ac.client.Close()
	}
	f.clients = map[string]*agentClient{}
}
