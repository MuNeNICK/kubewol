# syntax=docker/dockerfile:1.7

# ─────────────────────────────────────────
# Stage 1: compile the BPF C source to ELF.
#
# Runs on $TARGETPLATFORM (not $BUILDPLATFORM) so apt installs the
# right asm-generic / arch headers for the target CPU. This image
# runs under QEMU emulation when cross-building, which is slower
# than the Go stage below but necessary because BPF object files are
# arch-specific and depend on /usr/include/<arch>-linux-gnu/asm headers.
# ─────────────────────────────────────────
FROM debian:bookworm-slim AS bpfbuilder
ARG TARGETARCH
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        clang \
        llvm \
        libbpf-dev \
        linux-libc-dev \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /workspace
COPY bpf/ bpf/
RUN mkdir -p internal/ebpf && \
    case "$TARGETARCH" in \
      amd64)   BPF_ARCH=x86;   ASM_INCLUDE=/usr/include/x86_64-linux-gnu ;; \
      arm64)   BPF_ARCH=arm64; ASM_INCLUDE=/usr/include/aarch64-linux-gnu ;; \
      *) echo "unsupported TARGETARCH=$TARGETARCH" >&2; exit 1 ;; \
    esac; \
    clang -O2 -g -target bpf -D__TARGET_ARCH_${BPF_ARCH} \
        -I/usr/include -I"$ASM_INCLUDE" \
        -c bpf/monitor.c -o internal/ebpf/monitor.o

# ─────────────────────────────────────────
# Stage 2: build the Go binary.
#
# Runs on $BUILDPLATFORM and cross-compiles to $TARGETARCH because
# Go's native cross-compilation is far faster than QEMU. The freshly
# built monitor.o is copied in before `go build` so go:embed picks up
# the stage-1 output rather than whatever the host committed.
# ─────────────────────────────────────────
FROM --platform=$BUILDPLATFORM golang:1.26 AS builder
ARG TARGETARCH
WORKDIR /workspace
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/
COPY --from=bpfbuilder /workspace/internal/ebpf/monitor.o internal/ebpf/monitor.o
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -a -o manager ./cmd/

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
