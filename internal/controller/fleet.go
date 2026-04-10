package controller

import (
	"context"
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
)

// SynEventHandler is invoked for every SSE event streamed from any agent.
type SynEventHandler func(ctx context.Context, evt agentapi.SynEventMsg)

// Fleet maintains an up-to-date list of kubewol-agent pods (one per node) by
// watching the EndpointSlices for the agent headless Service, keeps a
// per-pod SSE subscription for direct-scale events, and fans a WatchSpec out
// to every reachable agent on PushAll.
//
// It is meant to satisfy the AgentFleet interface the reconciler expects.
type Fleet struct {
	k8s        client.Client
	logger     logr.Logger
	namespace  string
	serviceKey string // e.g. "kubewol-agent" — matches EndpointSlice label
	port       int    // agent HTTPS port
	onEvent    SynEventHandler

	mu      sync.Mutex
	clients map[string]*agentClient // keyed by "ip:port"
}

type agentClient struct {
	base   string // https://ip:port
	client *agentapi.Client
	cancel context.CancelFunc
}

// NewFleet constructs a Fleet. namespace is the namespace the agent DaemonSet
// runs in; serviceKey is the headless Service name; port is the agent HTTPS
// port (typically 8443).
func NewFleet(k8s client.Client, logger logr.Logger, namespace, serviceKey string, port int, onEvent SynEventHandler) *Fleet {
	return &Fleet{
		k8s:        k8s,
		logger:     logger.WithName("fleet"),
		namespace:  namespace,
		serviceKey: serviceKey,
		port:       port,
		onEvent:    onEvent,
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
	// which rebuilds the per-pod client set and opens/closes SSE streams.
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
	defer f.mu.Unlock()
	// Add new clients.
	for key := range seen {
		if _, ok := f.clients[key]; ok {
			continue
		}
		base := "https://" + key
		c, err := agentapi.NewClient(base, "")
		if err != nil {
			f.logger.Error(err, "new agent client", "base", base)
			continue
		}
		subCtx, cancel := context.WithCancel(context.Background())
		ac := &agentClient{base: base, client: c, cancel: cancel}
		f.clients[key] = ac
		go f.runSubscription(subCtx, ac)
		f.logger.Info("agent registered", "base", base)
	}
	// Drop stale clients.
	for key, ac := range f.clients {
		if _, ok := seen[key]; ok {
			continue
		}
		ac.cancel()
		delete(f.clients, key)
		f.logger.Info("agent dropped", "base", ac.base)
	}
	return nil
}

// runSubscription opens an SSE stream and reconnects with backoff until the
// client's context is cancelled by refresh().
func (f *Fleet) runSubscription(ctx context.Context, ac *agentClient) {
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		err := ac.client.StreamSynEvents(ctx, func(evt agentapi.SynEventMsg) {
			if f.onEvent != nil {
				f.onEvent(ctx, evt)
			}
		})
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			f.logger.V(1).Info("SSE disconnected", "agent", ac.base, "error", err.Error())
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

// PushAll fans the given WatchSpec out to every known agent in parallel.
// Failures are logged but not returned so a single unreachable node cannot
// stall every other reconcile.
func (f *Fleet) PushAll(ctx context.Context, spec agentapi.WatchSpec) error {
	f.mu.Lock()
	targets := make([]*agentClient, 0, len(f.clients))
	for _, ac := range f.clients {
		targets = append(targets, ac)
	}
	f.mu.Unlock()

	if len(targets) == 0 {
		f.logger.V(1).Info("PushAll: no agents yet")
		return nil
	}

	var wg sync.WaitGroup
	var errMu sync.Mutex
	var firstErr error
	for _, ac := range targets {
		wg.Add(1)
		go func(ac *agentClient) {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			if err := ac.client.PutWatches(cctx, spec); err != nil {
				f.logger.V(1).Info("PutWatches failed", "agent", ac.base, "error", err.Error())
				errMu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				errMu.Unlock()
			}
		}(ac)
	}
	wg.Wait()
	// Do not surface the first error; reconcile will retry on the next event.
	_ = firstErr
	return nil
}

func (f *Fleet) closeAll() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, ac := range f.clients {
		ac.cancel()
	}
	f.clients = map[string]*agentClient{}
}
