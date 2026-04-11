// Package agentapi is the bridge between the kubewol controller Deployment
// and the kubewol agent DaemonSet. The wire format is gRPC (defined in
// proto/kubewol/v1/agent.proto); this file hosts the controller-side helper
// that opens a connection to one agent Pod and refreshes its audience-bound
// bearer token per RPC.
//
// Authentication model:
//   - Transport: TLS. If ClientOptions.CAFile is set the controller verifies
//     the agent's certificate against that CA bundle. Otherwise the client
//     falls back to InsecureSkipVerify because the agent mints a self-signed
//     cert in-memory at startup; this matches controller-runtime's metrics
//     server default. Operators who want full peer verification distribute
//     a shared CA (for example via cert-manager) and point --agent-tls-ca-file
//     at the mounted bundle.
//   - Bearer token: a projected ServiceAccount token with
//     audience=kubewol.io/agent-api. The agent's gRPC auth interceptor
//     validates it via TokenReview with spec.audiences set, so a leaked
//     token cannot be replayed against kube-apiserver or any other
//     audience-unchecked in-cluster service. This is the primary defence;
//     TLS verification above is defence-in-depth.
package agentapi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"

	pb "github.com/munenick/kubewol/internal/agentapi/pb"
)

// DefaultAudienceTokenPath is the projected volume path for the audience-bound
// ServiceAccount token.
const DefaultAudienceTokenPath = "/var/run/secrets/kubewol/agent-api/token"

// ClientOptions configures TLS + token sourcing for a Client. An empty
// struct selects kubewol defaults: InsecureSkipVerify + the audience-bound
// token at DefaultAudienceTokenPath.
type ClientOptions struct {
	// TokenPath overrides the bearer token file. Empty means use
	// DefaultAudienceTokenPath.
	TokenPath string
	// CAFile is the path to a PEM-encoded CA bundle the client uses to
	// verify the agent certificate. Empty means InsecureSkipVerify.
	CAFile string
	// ServerName is the SNI / X.509 hostname the agent cert must present.
	// Ignored when CAFile is empty.
	ServerName string
}

// Client wraps a grpc.ClientConn and the audience-bound token file, handing
// back a pb.AgentClient that automatically attaches the bearer token to
// every outgoing RPC. One Client per agent pod IP; the controller Fleet
// creates and discards them as EndpointSlice changes.
type Client struct {
	conn      *grpc.ClientConn
	pb        pb.AgentClient
	tokenPath string

	mu    sync.Mutex
	token string
}

// NewClient dials the given target (host:port) and returns a Client. The
// target is passed to grpc.NewClient directly; scheme is implicit.
// tokenPath is a legacy-friendly shorthand; prefer NewClientWithOptions for
// new call sites that need TLS verification.
func NewClient(target, tokenPath string) (*Client, error) {
	return NewClientWithOptions(target, ClientOptions{TokenPath: tokenPath})
}

// NewClientWithOptions is the full-fat constructor. If CAFile is set the
// client verifies the agent certificate against that bundle; otherwise it
// falls back to InsecureSkipVerify as documented at the package level.
func NewClientWithOptions(target string, opts ClientOptions) (*Client, error) {
	tokenPath := opts.TokenPath
	if tokenPath == "" {
		tokenPath = DefaultAudienceTokenPath
	}
	// Verify the file is readable up-front so misconfiguration fails fast.
	if _, err := os.ReadFile(tokenPath); err != nil {
		return nil, fmt.Errorf("read SA token %s: %w", tokenPath, err)
	}

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if opts.CAFile != "" {
		caPEM, err := os.ReadFile(opts.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read CA bundle %s: %w", opts.CAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("CA bundle %s: no PEM certificates", opts.CAFile)
		}
		tlsCfg.RootCAs = pool
		tlsCfg.ServerName = opts.ServerName
	} else {
		// Self-signed agent cert; TokenReview is the primary authorization.
		tlsCfg.InsecureSkipVerify = true
	}

	conn, err := grpc.NewClient(target,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(4*1024*1024),
			grpc.MaxCallSendMsgSize(4*1024*1024),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("grpc dial %s: %w", target, err)
	}
	return &Client{
		conn:      conn,
		pb:        pb.NewAgentClient(conn),
		tokenPath: tokenPath,
	}, nil
}

// Close shuts down the underlying grpc.ClientConn.
func (c *Client) Close() error {
	if c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

// withToken attaches a fresh Bearer token to the outgoing context. Projected
// ServiceAccount tokens are rotated by kubelet well before expiry, so the
// in-memory token becomes stale if cached for the full process lifetime.
func (c *Client) withToken(ctx context.Context) (context.Context, error) {
	tok, err := c.currentToken()
	if err != nil {
		return nil, err
	}
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+tok), nil
}

func (c *Client) currentToken() (string, error) {
	b, err := os.ReadFile(c.tokenPath)
	if err != nil {
		return "", fmt.Errorf("read SA token: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}

// PutWatches replaces the agent's full desired state in one RPC.
func (c *Client) PutWatches(ctx context.Context, spec *pb.WatchSpec) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	ctx, err := c.withToken(ctx)
	if err != nil {
		return err
	}
	_, err = c.pb.PutWatches(ctx, spec)
	return err
}

// StreamSynEvents opens a server-side stream and calls onEvent for every
// direct-scale-eligible SynEvent until the stream disconnects. Caller is
// expected to wrap this in a retry loop with backoff.
func (c *Client) StreamSynEvents(ctx context.Context, onEvent func(*pb.SynEvent)) error {
	ctx, err := c.withToken(ctx)
	if err != nil {
		return err
	}
	stream, err := c.pb.SubscribeSynEvents(ctx, &pb.SubscribeRequest{})
	if err != nil {
		return fmt.Errorf("SubscribeSynEvents: %w", err)
	}
	for {
		evt, err := stream.Recv()
		if err != nil {
			return err
		}
		onEvent(evt)
	}
}
