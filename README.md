# kubewol

Wake-on-LAN for Kubernetes. eBPF detects TCP SYN and wakes scaled-to-zero workloads.

kubewol is an eBPF-based traffic sensor and Prometheus exporter that enables HPA scale-to-zero with TCP connection preservation. It requires the [HPA `HPAScaleToZero` feature gate](https://kubernetes.io/docs/reference/command-line-tools-reference/feature-gates/) (Alpha since v1.16, [improved in v1.36 with `ScaledToZero` condition](https://github.com/kubernetes/kubernetes/pull/135118)).

## How it works

```
replicas=0:
  Client ── SYN ──> eBPF silently holds the connection
                    SYN count → Prometheus → HPA scales 0→N

Pod Ready:
  SYN retransmit → Pod → connection established (same TCP socket)
```

- **No proxy, no sidecar.** Request path is unchanged: `Client -> Service -> Pod`.
- **Prometheus native.** Standard /metrics exporter + optional Remote Write for fast cold start. Compatible with existing metrics providers.
- **TCP connection preserved.** The client's TCP connection survives the cold start transparently. No reconnection or retry logic needed.

## Prerequisites

- Kubernetes **v1.36+** with `HPAScaleToZero=true` feature gate enabled ([docs](https://kubernetes.io/docs/reference/command-line-tools-reference/feature-gates/))
- Linux kernel **6.6+** (for TCX BPF link support)
- **Prometheus** + **Prometheus Adapter** (for HPA external metrics)

## Install

```bash
kubectl apply -f https://github.com/munenick/kubewol/releases/latest/download/install.yaml
```

Or build from source:

```bash
# Compile eBPF (requires clang + kernel headers)
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include \
  -c bpf/monitor.c -o internal/ebpf/monitor.o

# Deploy
make docker-build IMG=ghcr.io/munenick/kubewol:latest
make deploy IMG=ghcr.io/munenick/kubewol:latest
```

## Usage

### 1. Annotate the Service

```bash
kubectl annotate svc my-app kubewol/enabled=true
```

That's it. kubewol will start monitoring TCP SYN traffic to this Service.

Optional: if the Deployment name differs from the Service name:

```bash
kubectl annotate svc my-app kubewol/deployment=my-deploy
```

### 2. Configure Prometheus Adapter

Add a rule for `ebpf_service_syn_total` to your Prometheus Adapter config:

```yaml
rules:
  external:
    - seriesQuery: 'ebpf_service_syn_total'
      resources:
        overrides:
          namespace: {resource: "namespace"}
      name:
        matches: "^(.*)$"
        as: "${1}"
      metricsQuery: 'sum(rate(<<.Series>>{<<.LabelMatchers>>}[1m])) or vector(0)'
```

### 3. Create an HPA with `minReplicas: 0`

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: my-app
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: my-app
  minReplicas: 0
  maxReplicas: 10
  metrics:
    - type: External
      external:
        metric:
          name: ebpf_service_syn_total
        target:
          type: Value
          value: "100m"
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 10
      policies:
        - type: Percent
          value: 100
          periodSeconds: 15
    scaleUp:
      stabilizationWindowSeconds: 0
      selectPolicy: Max
      policies:
        - type: Percent
          value: 100
          periodSeconds: 15
        - type: Pods
          value: 5
          periodSeconds: 15
```

> **Important:** `scaleUp` must include a `Pods` type policy. `Percent`-only cannot scale from 0 (100% of 0 = 0).

### 4. Done

When no traffic arrives, HPA scales the Deployment to 0. When a TCP SYN is detected:

1. kubewol counts it and exposes via Prometheus `/metrics`
2. Prometheus scrapes it (or kubewol pushes via Remote Write for speed)
3. Prometheus Adapter exposes as external metric
4. HPA sees `ebpf_service_syn_total > 0` and scales up
5. The client's TCP connection is preserved through SYN retransmit

## Annotations

| Annotation | Required | Default | Description |
|---|---|---|---|
| `kubewol/enabled` | Yes | - | Set to `"true"` to enable monitoring |
| `kubewol/target-name` | No | Service name | Target workload name if different from Service |
| `kubewol/direct-scale` | No | `false` | Set to `"true"` to bypass HPA for 0→1 (fast path, see below) |

The target workload kind (`Deployment` or `StatefulSet`) is auto-detected. Both are supported.

### Direct scale (fast path)

By default, kubewol is a pure Prometheus exporter and HPA handles all scaling decisions. Cold start is ~19s (dominated by HPA 15s sync period).

Setting `kubewol/direct-scale=true` on **both** the Service AND the target workload enables a fast path:

```bash
kubectl annotate svc my-app kubewol/direct-scale=true
kubectl annotate deploy my-app kubewol/direct-scale=true
```

Requiring the annotation on the target workload too prevents privilege escalation: a user who can only mutate Services cannot redirect kubewol to patch arbitrary workloads.

- On SYN detection, kubewol reads the current scale and patches `deployments/scale` or `statefulsets/scale` to **1 only if currently at 0**. Existing replicas from HPA or manual scale-up are never clobbered. Conflict errors (races between nodes or with HPA) are retried.
- Cold start drops from ~19s to **~3s**
- HPA still handles 1→N and N→0 (kubewol only triggers 0→1)
- Coexists with HPA: kubewol wins the race to 1, then HPA takes over

**This fast path requires an opt-in ClusterRole** because the controller needs cluster-wide write on `deployments/scale` and `statefulsets/scale`. The default install does NOT include this. Apply it explicitly:

```bash
kubectl apply -f https://github.com/munenick/kubewol/releases/latest/download/direct-scale-role.yaml
```

Without this role, kubewol still observes traffic and feeds metrics to HPA, but `TriggerScale` calls will fail with `forbidden`.

Useful when:
- You want the absolute fastest cold start
- You can't install Prometheus + Adapter (kubewol works standalone for 0→1)
- You need to avoid KEDA's External Metrics API conflict

## Securing the metrics endpoint

The DaemonSet binds `/metrics` to `hostPort: 9090` on every node. Anything on the node network can scrape service names and SYN counts unless restricted. Apply the provided NetworkPolicy and label your Prometheus namespace:

```bash
kubectl apply -f config/network-policy/allow-metrics-traffic.yaml
kubectl label ns monitoring kubewol-metrics=scraper
```

Only pods in namespaces labeled `kubewol-metrics=scraper` will be able to reach port 9090.

## Flags

| Flag | Default | Description |
|---|---|---|
| `--metrics-bind-address` | `:9090` | Prometheus /metrics bind address |
| `--health-probe-bind-address` | `:8081` | Health probe bind address |
| `--remote-write-url` | (disabled) | Prometheus Remote Write URL for fast cold start push (e.g. `http://prometheus:9090/api/v1/write`) |

## Fast cold start with Remote Write

By default, kubewol relies on Prometheus scraping `/metrics`. The cold start latency depends on the scrape interval (typically 15-60s).

To reduce cold start to ~25s, enable [Prometheus Remote Write receiver](https://prometheus.io/docs/prometheus/latest/configuration/configuration/#remote_write_receiver) and pass the URL:

```yaml
# In DaemonSet args:
- --remote-write-url=http://prometheus-server.monitoring.svc:80/api/v1/write
```

When a SYN is detected for a scaled-to-zero service, kubewol immediately pushes the metric, bypassing the scrape interval.

## Architecture

```
kubewol DaemonSet (one per node, read-only RBAC)
  |
  +-- TC ingress (eBPF)
  |     proxy_mode map: SYN counting + SYN DROP when no endpoints
  |
  +-- TC egress (eBPF)
  |     rst_suppress map: RST/ICMP DROP (stays ON 5s after proxy_mode OFF
  |                       to cover kube-proxy iptables propagation delay)
  |
  +-- controller-runtime Reconciler
  |     Watches: Service (annotation) -> BPF watch map
  |     Watches: EndpointSlice        -> proxy_mode / rst_suppress toggle
  |
  +-- Prometheus exporter (:9090/metrics)
  |     ebpf_service_syn_total counter from BPF map
  |
  +-- Remote Write push (optional)
        On SYN detection -> POST to Prometheus /api/v1/write

External (not part of kubewol):
  Prometheus -> Prometheus Adapter -> HPA
```

## Performance

Measured on kind (K8s v1.36.0-rc.0, kernel 6.19, 2-node cluster, default HPA settings) with a Python HTTP server as the workload.

### Cold start: TCP connect time (0 replicas -> HTTP 200)

| Mode | Target | Scale API call | Total cold start |
|---|---|---|---|
| HPA (default) | Deployment | — | **~19.7s** |
| direct-scale | Deployment | 24.8 ms | **~3.0s** |
| direct-scale | StatefulSet | 9.2 ms | **~4.1s** |

A single `curl` succeeds without application-level retries. The TCP connection is preserved through kernel SYN retransmit — no reconnection, no retry logic needed.

### Time breakdown (HPA mode)

```
t=0.0s    SYN -> TC ingress DROP (conntrack clean)
t=1.0s    SYN retransmit #1 -> DROP
t=3.0s    SYN retransmit #2 -> DROP
          ~~ Remote Write pushes metric to Prometheus ~~
          ~~ Prometheus Adapter picks up metric ~~
t=7.0s    SYN retransmit #3 -> DROP
          ~~ HPA evaluates, scales 0->N ~~
t=15.0s   SYN retransmit #4 -> DROP
          ~~ Pod scheduling + container start + readiness probe ~~
t=~18s    Pod Ready -> EndpointSlice updated -> proxy_mode OFF
t=~19s    SYN retransmit #5 -> PASS -> TCP handshake -> HTTP 200
```

### Time breakdown (direct-scale mode)

```
t=0.0s    SYN -> TC ingress DROP + ring buffer event
t=~0.01s  kubewol patches /scale (0->1) via K8s API  <-- bypasses HPA 15s sync
t=1.0s    SYN retransmit #1 -> DROP (pod still starting)
t=~2-3s   Pod Ready -> EndpointSlice updated -> proxy_mode OFF
t=~3s     SYN retransmit #2 -> PASS -> TCP handshake -> HTTP 200
```

### Bottlenecks

| Component | Contribution | Tunable | Scope |
|---|---|---|---|
| **HPA sync period** | up to 15s | `--horizontal-pod-autoscaler-sync-period` on kube-controller-manager | Cluster-wide |
| **Prometheus Adapter relist** | up to 30s | `--metrics-relist-interval` on Prometheus Adapter | Per-deployment |
| **Prometheus scrape interval** | up to 60s | `scrape_interval` in Prometheus config | **Bypassed by Remote Write** |
| **Pod startup** | 3-5s | Image pre-pull, lightweight base image | Per-workload |
| **TCP SYN retransmit** | 0-16s | Not tunable from server side | Kernel exponential backoff |

In HPA mode, the dominant bottleneck is the **HPA 15s sync period**. This is not configurable per-HPA; it is a global kube-controller-manager flag. **direct-scale mode bypasses this entirely** and is ~6x faster.

### Tuning guide

| Optimization | Cold start reduction |
|---|---|
| **`kubewol/direct-scale=true`** | **-16s (19.7s → 3s)** |
| Enable Remote Write (`--remote-write-url`) | Eliminates scrape interval wait (HPA mode) |
| `--metrics-relist-interval=10s` on Adapter | -20s worst case (HPA mode) |
| `--horizontal-pod-autoscaler-sync-period=5s` | -10s worst case (HPA mode) |
| Pre-pull workload images | -1-2s |
| Static binary / distroless base | -1-2s |
| **direct-scale + tuned Pod** | **~1-2s cold start** |

### Limitations

- **IPv4 only.** The TC eBPF programs parse IPv4 headers only. IPv6 and dual-stack Services are explicitly skipped (logged as `skipping non-IPv4 service`).
- **HPA evaluation frequency** is global, not per-HPA
- **TCP SYN retransmit backoff** is kernel-level (1, 2, 4, 8, 16s intervals); after Pod is ready, the client waits for its next scheduled retransmit
- **kube-proxy endpoint propagation** adds delay between Pod Ready and iptables/ipvs rule update

## Uninstall

```bash
kubectl delete -f https://github.com/munenick/kubewol/releases/latest/download/install.yaml
```

Remove annotations from services:

```bash
kubectl annotate svc my-app kubewol/enabled-
```

## License

Apache License 2.0
