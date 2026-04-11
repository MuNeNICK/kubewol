# syntax=docker/dockerfile:1.7

# ─────────────────────────────────────────
# Stage 1: compile the BPF C source to ELF.
#
# Done in a pinned Debian builder rather than on the host so the committed
# internal/ebpf/monitor.o cannot drift relative to bpf/monitor.c — every
# image build reruns clang against the same source tree that go:embed will
# pick up in stage 2.
# ─────────────────────────────────────────
FROM debian:bookworm-slim AS bpfbuilder
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        clang \
        llvm \
        libbpf-dev \
        linux-libc-dev \
        gcc-multilib \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /workspace
COPY bpf/ bpf/
RUN mkdir -p internal/ebpf && \
    ARCH="$(uname -m)"; \
    case "$ARCH" in \
      x86_64)  ASM_INCLUDE=/usr/include/x86_64-linux-gnu ;; \
      aarch64) ASM_INCLUDE=/usr/include/aarch64-linux-gnu ;; \
      *)       ASM_INCLUDE="/usr/include/$ARCH-linux-gnu" ;; \
    esac; \
    clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
        -I/usr/include -I"$ASM_INCLUDE" \
        -c bpf/monitor.c -o internal/ebpf/monitor.o

# ─────────────────────────────────────────
# Stage 2: build the Go binary.
# The freshly-compiled monitor.o is copied in before `go build`, so go:embed
# always sees the output of stage 1 rather than whatever the host committed.
# ─────────────────────────────────────────
FROM golang:1.26 AS builder
WORKDIR /workspace
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/
COPY --from=bpfbuilder /workspace/internal/ebpf/monitor.o internal/ebpf/monitor.o
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -o manager ./cmd/

# ─────────────────────────────────────────
# Stage 3: final image.
# Two copies of the same binary:
#   /manager       — setcap'd for the agent DaemonSet
#   /manager-plain — no file caps, used by the controller Deployment
#
# File caps are needed by the agent: a non-root process that execs a binary
# without file caps loses its effective capability set on exec, even if the
# container runtime attached caps to the pod via SecurityContext.capabilities.
# bpf(BPF_PROG_LOAD) then returns EPERM.
#
# The controller is unprivileged (NoNewPrivs is implicit when
# allowPrivilegeEscalation=false) and the kernel refuses to exec a binary
# with file capabilities under NoNewPrivs unless those caps are in the
# bounding set. /manager-plain sidesteps that with zero file caps.
# ─────────────────────────────────────────
FROM alpine:3.21
RUN apk add --no-cache ca-certificates libcap
COPY --from=builder /workspace/manager /manager
COPY --from=builder /workspace/manager /manager-plain
RUN setcap cap_bpf,cap_net_admin=eip /manager
USER 65532:65532
ENTRYPOINT ["/manager"]
