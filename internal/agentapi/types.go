// Package agentapi defines the wire types and HTTP client used between the
// kubewol controller (Deployment, unprivileged) and the kubewol agent
// (DaemonSet, hostNetwork + CAP_BPF + CAP_NET_ADMIN).
//
// The controller owns the reconcile loop against the Kubernetes API and tells
// each agent what BPF state to hold. The agent owns the BPF programs and maps,
// plus the ring buffer reader, and streams SYN events back to the controller
// so direct-scale decisions can be made in the unprivileged controller.
//
// Transport is plain HTTPS + ServiceAccount bearer token validated via the
// Kubernetes TokenReview / SubjectAccessReview filter that already protects
// the metrics endpoint. The agent reuses the controller-runtime metrics
// server's ExtraHandlers, so there is no second listener to secure.
package agentapi

// PathWatches is the HTTP path the controller PUTs to push the full desired
// watch state for this agent.
const PathWatches = "/v1/watches"

// PathSynEvents is the HTTP path the controller opens as an SSE stream to
// receive SYN events for direct-scale services.
const PathSynEvents = "/v1/syn-events"

// WatchSpec is the complete desired state for a single agent. The agent
// replaces its in-memory and BPF state to match this spec on every PUT.
type WatchSpec struct {
	Watches []WatchEntry `json:"watches"`
}

// WatchEntry describes one Service that the agent must track. A Service with
// multiple TCP ports yields multiple entries; they share Namespace / Service /
// Target and only differ in Port / NodePort.
type WatchEntry struct {
	Namespace   string `json:"namespace"`
	Service     string `json:"service"`
	TargetKind  string `json:"targetKind"`  // "Deployment" or "StatefulSet"
	TargetName  string `json:"targetName"`
	ClusterIP   string `json:"clusterIP"`   // IPv4 dotted quad
	Port        uint16 `json:"port"`
	NodePort    int32  `json:"nodePort"`    // 0 when none
	ProxyMode   bool   `json:"proxyMode"`   // SYN DROP on ingress
	RstSuppress bool   `json:"rstSuppress"` // RST/ICMP DROP on egress
	DirectScale bool   `json:"directScale"` // emit SSE events for direct-scale
}

// Key returns the logical key used to dedupe and debounce entries.
func (e *WatchEntry) Key() string {
	return e.Namespace + "/" + e.Service
}

// SynEventMsg is the JSON payload streamed back to the controller over SSE
// when a SYN hits a watched service that has DirectScale enabled. The agent
// already resolves src/dst addresses to a target workload so the controller
// can fire the K8s scale call with no extra lookups.
type SynEventMsg struct {
	Namespace  string `json:"namespace"`
	TargetKind string `json:"targetKind"`
	TargetName string `json:"targetName"`
}
