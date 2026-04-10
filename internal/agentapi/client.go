package agentapi

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultAudienceTokenPath is the projected volume path for the audience-bound
// ServiceAccount token. The controller Deployment mounts a projected token
// with audience kubewol.io/agent-api there so that a leaked bearer can only
// be replayed against kubewol agents, not against kube-apiserver or any
// other audience-unchecked Kubernetes component.
const DefaultAudienceTokenPath = "/var/run/secrets/kubewol/agent-api/token"

// FallbackTokenPath is the default ServiceAccount volume path. Used when the
// audience-bound volume is not mounted (e.g. older manifests / unit tests).
const FallbackTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

// sseIdleTimeout is how long StreamSynEvents will tolerate no bytes from the
// agent before closing the connection and surfacing an error. The agent emits
// ":ka\n\n" SSE comments every 20 seconds, so 60 seconds gives a 3x margin
// before the client decides the connection is dead.
const sseIdleTimeout = 60 * time.Second

// Client talks to one agent HTTP endpoint on behalf of the controller.
// One Client per agent pod IP. The controller creates / discards Clients as
// EndpointSlice changes.
type Client struct {
	base      string // https://<pod-ip>:<port>
	tokenPath string // projected volume path; re-read on every request
	hc        *http.Client
}

// NewClient builds a Client for the given base URL (scheme://host:port).
// tokenPath should point at a projected ServiceAccount token; if empty the
// audience-bound path at DefaultAudienceTokenPath is tried first, then the
// legacy SA path is used as a fallback.
//
// TLS: InsecureSkipVerify is set because the agent presents a self-signed
// certificate generated in-memory by the controller-runtime metrics server.
// Verifying it would require cert-manager or an equivalent CA bootstrap.
// The residual MITM risk is mitigated by two defenses:
//   - Network path: agents and controllers only talk over the pod network;
//     NetworkPolicy scopes access to the kubewol-system controller pod.
//   - Token scope: the bearer presented here is an audience-bound projected
//     SA token (audience: kubewol.io/agent-api). Even if intercepted, the
//     kube-apiserver TokenReview on the agent side refuses any token whose
//     audience does not match, so the leaked credential cannot be replayed
//     against kube-apiserver or any other audience-unchecked service.
func NewClient(base, tokenPath string) (*Client, error) {
	if tokenPath == "" {
		if _, err := os.Stat(DefaultAudienceTokenPath); err == nil {
			tokenPath = DefaultAudienceTokenPath
		} else {
			tokenPath = FallbackTokenPath
		}
	}
	// Verify the file is readable up-front so misconfiguration fails fast.
	if _, err := os.ReadFile(tokenPath); err != nil {
		return nil, fmt.Errorf("read SA token %s: %w", tokenPath, err)
	}
	return &Client{
		base:      strings.TrimRight(base, "/"),
		tokenPath: tokenPath,
		hc: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}, nil
}

// currentToken re-reads the projected SA token file. Projected tokens are
// rotated by kubelet well before expiry, so the in-memory value becomes
// stale if cached once at startup.
func (c *Client) currentToken() (string, error) {
	b, err := os.ReadFile(c.tokenPath)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// PutWatches replaces the agent's full desired state.
func (c *Client) PutWatches(ctx context.Context, spec WatchSpec) error {
	body, err := json.Marshal(spec)
	if err != nil {
		return fmt.Errorf("marshal watches: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.base+PathWatches, bytes.NewReader(body))
	if err != nil {
		return err
	}
	token, err := c.currentToken()
	if err != nil {
		return fmt.Errorf("read SA token: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("PUT %s: %w", PathWatches, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("PUT %s: status %d: %s", PathWatches, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

// StreamSynEvents opens a long-lived SSE connection and calls onEvent for
// every SynEventMsg the agent emits until the context is cancelled or the
// connection drops. It returns whatever error ended the stream.
//
// Idle watchdog: the agent writes a ":ka\n\n" SSE comment every 20 seconds.
// If the client sees no bytes at all for sseIdleTimeout (60s) it concludes
// the connection is half-dead (TCP RST eaten by an intermediate path, or
// the agent blocked in kernel), cancels the request context, and returns.
// The caller is expected to wrap this in a retry loop.
func (c *Client) StreamSynEvents(ctx context.Context, onEvent func(SynEventMsg)) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Separate HTTP client: no total timeout, because SSE is long-lived.
	streamer := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
			ResponseHeaderTimeout: 10 * time.Second,
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+PathSynEvents, nil)
	if err != nil {
		return err
	}
	token, err := c.currentToken()
	if err != nil {
		return fmt.Errorf("read SA token: %w", err)
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := streamer.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", PathSynEvents, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("GET %s: status %d: %s", PathSynEvents, resp.StatusCode, strings.TrimSpace(string(b)))
	}

	// lastRead is monotonic-ish: nanoseconds since program start at the time
	// the scanner last returned a line. Updated on every read, checked by a
	// ticker goroutine that cancels the context on idle timeout.
	var lastRead int64
	atomic.StoreInt64(&lastRead, time.Now().UnixNano())
	var idleStop sync.WaitGroup
	idleStop.Add(1)
	go func() {
		defer idleStop.Done()
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				last := time.Unix(0, atomic.LoadInt64(&lastRead))
				if now.Sub(last) > sseIdleTimeout {
					cancel()
					return
				}
			}
		}
	}()
	defer idleStop.Wait()

	scanner := bufio.NewScanner(resp.Body)
	// Raise the line budget so a very large JSON does not truncate.
	scanner.Buffer(make([]byte, 0, 4096), 64*1024)
	for scanner.Scan() {
		atomic.StoreInt64(&lastRead, time.Now().UnixNano())
		line := scanner.Text()
		// Minimal SSE parser: we only emit "data: {...}" lines; ignore
		// keepalive comments (":ka") and empty separator lines.
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		payload := strings.TrimPrefix(line, "data: ")
		var evt SynEventMsg
		if err := json.Unmarshal([]byte(payload), &evt); err != nil {
			continue
		}
		onEvent(evt)
	}
	if err := scanner.Err(); err != nil && ctx.Err() == nil {
		return err
	}
	if ctx.Err() != nil {
		return fmt.Errorf("SSE idle watchdog cancelled: %w", ctx.Err())
	}
	return nil
}
