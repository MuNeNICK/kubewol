package agent

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	certutil "k8s.io/client-go/util/cert"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/munenick/kubewol/internal/agentapi/pb"
)

// GRPCService implements pb.AgentServer against an existing Agent. The service
// layer is intentionally thin: it translates protobuf messages to the in-memory
// agentapi types the Agent already understands, calls into Agent, and streams
// SYN events out to subscribers.
type GRPCService struct {
	pb.UnimplementedAgentServer
	agent *Agent
}

// NewGRPCService wires an Agent up to the gRPC surface described in
// proto/kubewol/v1/agent.proto.
func NewGRPCService(a *Agent) *GRPCService {
	return &GRPCService{agent: a}
}

// PutWatches replaces the agent's desired watch state with the message body
// and returns an empty response on success. Failures at the BPF layer surface
// as Internal errors so the controller retries on its next reconcile.
func (s *GRPCService) PutWatches(ctx context.Context, req *pb.WatchSpec) (*pb.PutWatchesResponse, error) {
	entries := make([]WatchEntrySpec, 0, len(req.GetWatches()))
	for _, w := range req.GetWatches() {
		entries = append(entries, WatchEntrySpec{
			Namespace:   w.GetNamespace(),
			Service:     w.GetService(),
			TargetKind:  w.GetTargetKind(),
			TargetName:  w.GetTargetName(),
			ClusterIP:   w.GetClusterIp(),
			Port:        uint16(w.GetPort()),
			NodePort:    w.GetNodePort(),
			ProxyMode:   w.GetProxyMode(),
			RstSuppress: w.GetRstSuppress(),
			DirectScale: w.GetDirectScale(),
		})
	}
	if err := s.agent.ApplyWatches(entries); err != nil {
		return nil, status.Errorf(codes.Internal, "apply watches: %v", err)
	}
	return &pb.PutWatchesResponse{}, nil
}

// SubscribeSynEvents opens a server-side stream that forwards every
// direct-scale-eligible SYN observed by the ring buffer reader until the
// client disconnects or the stream context is cancelled.
func (s *GRPCService) SubscribeSynEvents(_ *pb.SubscribeRequest, stream pb.Agent_SubscribeSynEventsServer) error {
	ch := s.agent.subscribe()
	defer s.agent.unsubscribe(ch)

	ctx := stream.Context()
	for {
		select {
		case <-ctx.Done():
			return nil
		case evt, ok := <-ch:
			if !ok {
				return nil
			}
			if err := stream.Send(&pb.SynEvent{
				Namespace:  evt.Namespace,
				TargetKind: evt.TargetKind,
				TargetName: evt.TargetName,
			}); err != nil {
				return err
			}
		}
	}
}

// ─────────────────────────────────────────
// TLS + authentication
// ─────────────────────────────────────────

// GenerateSelfSignedTLSConfig mints a self-signed certificate with SANs that
// cover the agent's expected listen addresses (pod IP is not known here;
// controller clients use InsecureSkipVerify and rely on the audience-bound
// token for authentication, so SANs are advisory).
//
// Mirrors the behaviour controller-runtime's metrics server uses for its own
// /metrics endpoint — we do the same thing here instead of piggy-backing on
// that listener because gRPC and HTTP are different wire protocols and need
// separate listeners.
func GenerateSelfSignedTLSConfig() (*tls.Config, error) {
	certPEM, keyPEM, err := certutil.GenerateSelfSignedCertKeyWithFixtures(
		"kubewol-agent",
		[]net.IP{net.IPv4(127, 0, 0, 1)},
		nil, "",
	)
	if err != nil {
		return nil, fmt.Errorf("generate self-signed cert: %w", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("tls x509 key pair: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// tokenReviewCache memoises recent TokenReview decisions so that the agent
// does not reissue a live TokenReview for every PutWatches / every
// SubscribeSynEvents reconnect. Kube-apiserver caches TokenReviews itself,
// but an in-agent cache also:
//   - caps agent → apiserver traffic under reconnect storms,
//   - lets us add a concurrency semaphore below without observable latency
//     for a legitimate steady-state caller,
//   - makes the negative path (wrong audience) cheap to refuse.
type tokenReviewCache struct {
	ttl      time.Duration
	mu       sync.Mutex
	entries  map[string]tokenReviewCacheEntry
	capacity int
}

type tokenReviewCacheEntry struct {
	decision bool
	deadline time.Time
}

func newTokenReviewCache(ttl time.Duration, capacity int) *tokenReviewCache {
	return &tokenReviewCache{
		ttl:      ttl,
		entries:  map[string]tokenReviewCacheEntry{},
		capacity: capacity,
	}
}

// lookup returns (decision, ok). ok=false means no fresh entry exists.
func (c *tokenReviewCache) lookup(key string) (bool, bool) {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		return false, false
	}
	if now.After(e.deadline) {
		delete(c.entries, key)
		return false, false
	}
	return e.decision, true
}

// store records a TokenReview decision. Purges aggressively once the map
// grows past capacity to keep the upper bound on memory.
func (c *tokenReviewCache) store(key string, decision bool) {
	deadline := time.Now().Add(c.ttl)
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= c.capacity {
		// Evict expired entries first; if still full, drop everything.
		now := time.Now()
		for k, v := range c.entries {
			if now.After(v.deadline) {
				delete(c.entries, k)
			}
		}
		if len(c.entries) >= c.capacity {
			c.entries = map[string]tokenReviewCacheEntry{}
		}
	}
	c.entries[key] = tokenReviewCacheEntry{decision: decision, deadline: deadline}
}

// authGate bundles the TokenReview cache and a semaphore that caps the
// number of in-flight TokenReview calls. An attacker hammering :8444 cannot
// amplify load on kube-apiserver beyond maxInflightTokenReviews concurrent
// calls because extra requests wait on the semaphore until their slot is
// available, then (usually) hit the cache once one legitimate call has
// primed it.
type authGate struct {
	k8s       kubernetes.Interface
	cache     *tokenReviewCache
	semaphore chan struct{}
}

const (
	tokenReviewCacheTTL      = 60 * time.Second
	tokenReviewCacheCapacity = 512
	maxInflightTokenReviews  = 8
)

func newAuthGate(k8s kubernetes.Interface) *authGate {
	return &authGate{
		k8s:       k8s,
		cache:     newTokenReviewCache(tokenReviewCacheTTL, tokenReviewCacheCapacity),
		semaphore: make(chan struct{}, maxInflightTokenReviews),
	}
}

// authenticate validates the incoming bearer token is bound to AgentAudience.
// Cache-first; cache miss fans through the concurrency semaphore.
func (g *authGate) authenticate(ctx context.Context) error {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "missing metadata")
	}
	auths := md.Get("authorization")
	if len(auths) == 0 {
		return status.Error(codes.Unauthenticated, "missing authorization metadata")
	}
	raw := auths[0]
	if !strings.HasPrefix(raw, "Bearer ") {
		return status.Error(codes.Unauthenticated, "authorization must be a bearer token")
	}
	token := strings.TrimPrefix(raw, "Bearer ")

	// Cache the SHA-256 of the token so the in-memory map does not
	// double as a token stash.
	sum := sha256.Sum256([]byte(token))
	key := hex.EncodeToString(sum[:])

	if decision, ok := g.cache.lookup(key); ok {
		if decision {
			return nil
		}
		return status.Errorf(codes.PermissionDenied,
			"token is not bound to audience %q", AgentAudience)
	}

	// Respect the in-flight cap. Under backpressure we block until a slot
	// is free or the caller's context is cancelled.
	select {
	case g.semaphore <- struct{}{}:
		defer func() { <-g.semaphore }()
	case <-ctx.Done():
		return status.Error(codes.DeadlineExceeded, "auth timed out waiting for token review slot")
	}

	tr, err := g.k8s.AuthenticationV1().TokenReviews().Create(ctx, &authv1.TokenReview{
		Spec: authv1.TokenReviewSpec{
			Token:     token,
			Audiences: []string{AgentAudience},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return status.Errorf(codes.Internal, "tokenreview: %v", err)
	}
	if !tr.Status.Authenticated {
		g.cache.store(key, false)
		return status.Errorf(codes.PermissionDenied,
			"token is not bound to audience %q", AgentAudience)
	}
	g.cache.store(key, true)
	return nil
}

// AuthInterceptors returns matched unary and stream gRPC interceptors that
// enforce audience-bound TokenReview on every incoming call. The underlying
// authGate caches decisions for tokenReviewCacheTTL and caps concurrent
// TokenReview fan-out.
func AuthInterceptors(k8s kubernetes.Interface) (grpc.UnaryServerInterceptor, grpc.StreamServerInterceptor) {
	gate := newAuthGate(k8s)
	unary := func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		if err := gate.authenticate(ctx); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
	stream := func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		if err := gate.authenticate(ss.Context()); err != nil {
			return err
		}
		return handler(srv, ss)
	}
	return unary, stream
}

// NewGRPCServer builds a grpc.Server with TLS credentials, audience-bound
// authentication interceptors (with TokenReview cache + concurrency cap),
// and the Agent service registered. Callers Serve() the returned server on
// their own listener.
func NewGRPCServer(a *Agent, k8s kubernetes.Interface, tlsCfg *tls.Config) *grpc.Server {
	unary, stream := AuthInterceptors(k8s)
	srv := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsCfg)),
		grpc.UnaryInterceptor(unary),
		grpc.StreamInterceptor(stream),
	)
	pb.RegisterAgentServer(srv, NewGRPCService(a))
	return srv
}
