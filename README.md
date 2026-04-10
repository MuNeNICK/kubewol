# kubewol

Wake-on-LAN for Kubernetes. eBPF detects TCP SYN and wakes scaled-to-zero workloads.

kubewol enables true scale-to-zero for Kubernetes workloads by combining eBPF traffic observation with the [HPA `HPAScaleToZero` feature gate](https://kubernetes.io/docs/reference/command-line-tools-reference/feature-gates/) (Alpha since v1.16, [improved in v1.36](https://github.com/kubernetes/kubernetes/pull/135118)).

## How it works

```
Client ── SYN ──> [ TC ingress: eBPF ] ── SYN DROP (no conntrack pollution)
                         |
                   SYN count -> External Metrics API -> HPA scales 0->N
                         |
                   [ TC egress: eBPF ] ── RST/ICMP suppression (fallback)
                         |
          Pod Ready -> proxy_mode OFF -> SYN passes through -> connection established
```

- **No proxy, no sidecar.** Request path is unchanged: `Client -> Service -> Pod`.
- **No Prometheus required.** kubewol serves the External Metrics API directly from BPF maps.
- **TCP connection is preserved.** SYN is silently dropped (not rejected), so the client's TCP stack retransmits. Once the Pod is ready, the retransmit succeeds on the same socket.

## Prerequisites

- Kubernetes **v1.36+** with `HPAScaleToZero=true` feature gate enabled
- Linux kernel **6.6+** (for TCX BPF link support)

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

### 2. Create an HPA with `minReplicas: 0`

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
          value: "1"
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 30
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

> **Important:** The `scaleUp` section must include a `Pods` type policy. A `Percent`-only policy cannot scale from 0 (100% of 0 = 0).

### 3. Done

When no traffic arrives, HPA scales the Deployment to 0. When a TCP SYN is detected:

1. kubewol counts it and exposes via External Metrics API
2. HPA sees `ebpf_service_syn_total > 0` and scales up
3. The client's TCP connection is preserved through SYN retransmit

## Annotations

| Annotation | Required | Default | Description |
|---|---|---|---|
| `kubewol/enabled` | Yes | - | Set to `"true"` to enable monitoring |
| `kubewol/deployment` | No | Service name | Deployment name if different from Service |

## Architecture

```
kubewol DaemonSet (one per node)
  |
  +-- TC ingress (eBPF)
  |     SYN counting
  |     SYN DROP when no endpoints (preserves TCP connection)
  |
  +-- TC egress (eBPF)
  |     RST/ICMP suppression (race condition fallback)
  |
  +-- controller-runtime Reconciler
  |     Watches: Service (annotation), EndpointSlice (proxy_mode)
  |
  +-- External Metrics API server (:6443)
        BPF map -> windowed SYN count -> HPA
```

## Uninstall

```bash
kubectl delete -f https://github.com/munenick/kubewol/releases/latest/download/install.yaml
```

## License

Apache License 2.0
