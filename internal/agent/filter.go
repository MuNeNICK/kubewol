package agent

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/util/wait"
	apiserverapi "k8s.io/apiserver/pkg/apis/apiserver"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/authenticatorfactory"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/authorization/authorizerfactory"
	authenticationv1 "k8s.io/client-go/kubernetes/typed/authentication/v1"
	authorizationv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
	"k8s.io/client-go/rest"

	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

// KubewolFilterProvider returns a metrics.FilterProvider compatible with
// controller-runtime's metrics server, but with a critical change from the
// upstream filters.WithAuthenticationAndAuthorization: it configures the
// DelegatingAuthenticator with an explicit APIAudiences list that accepts
// BOTH
//
//  1. The apiserver's default audience (so ordinary ServiceAccount tokens,
//     e.g. the ones Prometheus scrapers mount, still authenticate for
//     /metrics requests).
//  2. AgentAudience ("kubewol.io/agent-api") so the controller's
//     audience-bound projected token is accepted for /v1/* requests.
//
// Upstream passes no APIAudiences, which makes the TokenReview default to
// the apiserver's own audience; that hard-fails audience-bound tokens
// with "token audiences [X] is invalid for target audiences [Y]".
func KubewolFilterProvider(defaultAPIAudience string) func(c *rest.Config, httpClient *http.Client) (metricsserver.Filter, error) {
	targetAudiences := []string{AgentAudience}
	if defaultAPIAudience != "" {
		targetAudiences = append(targetAudiences, defaultAPIAudience)
	}

	return func(config *rest.Config, httpClient *http.Client) (metricsserver.Filter, error) {
		authnClient, err := authenticationv1.NewForConfigAndClient(config, httpClient)
		if err != nil {
			return nil, err
		}
		authzClient, err := authorizationv1.NewForConfigAndClient(config, httpClient)
		if err != nil {
			return nil, err
		}

		authenticatorConfig := authenticatorfactory.DelegatingAuthenticatorConfig{
			Anonymous: &apiserverapi.AnonymousAuthConfig{Enabled: false},
			CacheTTL:  1 * time.Minute,
			// APIAudiences is the list of audiences the TokenReview call
			// asks the apiserver to accept. Any value in here is ok.
			APIAudiences:             authenticator.Audiences(targetAudiences),
			TokenAccessReviewClient:  authnClient,
			TokenAccessReviewTimeout: 10 * time.Second,
			WebhookRetryBackoff: &wait.Backoff{
				Duration: 500 * time.Millisecond,
				Factor:   1.5,
				Jitter:   0.2,
				Steps:    5,
			},
		}
		delegatingAuthenticator, _, err := authenticatorConfig.New()
		if err != nil {
			return nil, fmt.Errorf("failed to create authenticator: %w", err)
		}

		authorizerConfig := authorizerfactory.DelegatingAuthorizerConfig{
			SubjectAccessReviewClient: authzClient,
			AllowCacheTTL:             5 * time.Minute,
			DenyCacheTTL:              30 * time.Second,
			WebhookRetryBackoff: &wait.Backoff{
				Duration: 500 * time.Millisecond,
				Factor:   1.5,
				Jitter:   0.2,
				Steps:    5,
			},
		}
		delegatingAuthorizer, err := authorizerConfig.New()
		if err != nil {
			return nil, fmt.Errorf("failed to create authorizer: %w", err)
		}

		return func(log logr.Logger, handler http.Handler) (http.Handler, error) {
			log.V(1).Info("kubewol metrics filter installed", "audiences", targetAudiences)
			return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				// Inject the target audience list into the request context.
				// The webhook token authenticator reads audiences from the
				// context via authenticator.AudiencesFrom(ctx), not from the
				// DelegatingAuthenticatorConfig's APIAudiences field, so
				// without this call TokenReview is sent with spec.audiences
				// empty and the apiserver falls back to its default audience
				// (https://kubernetes.default.svc.cluster.local). Any
				// audience-bound token then fails validation.
				ctx := authenticator.WithAudiences(req.Context(), authenticator.Audiences(targetAudiences))
				req = req.WithContext(ctx)

				res, ok, err := delegatingAuthenticator.AuthenticateRequest(req)
				if err != nil {
					log.V(1).Info("Authentication failed", "path", req.URL.Path, "error", err.Error())
					http.Error(w, "Authentication failed", http.StatusUnauthorized)
					return
				}
				if !ok {
					log.V(1).Info("Authentication rejected", "path", req.URL.Path)
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}

				attributes := authorizer.AttributesRecord{
					User: res.User,
					Verb: strings.ToLower(req.Method),
					Path: req.URL.Path,
				}
				authorized, reason, err := delegatingAuthorizer.Authorize(ctx, attributes)
				if err != nil {
					msg := fmt.Sprintf("Authorization for user %s failed", attributes.User.GetName())
					log.Error(err, msg)
					http.Error(w, msg, http.StatusInternalServerError)
					return
				}
				if authorized != authorizer.DecisionAllow {
					msg := fmt.Sprintf("Authorization denied for user %s", attributes.User.GetName())
					log.V(4).Info(fmt.Sprintf("%s: %s", msg, reason))
					http.Error(w, msg, http.StatusForbidden)
					return
				}

				handler.ServeHTTP(w, req)
			}), nil
		}, nil
	}
}
