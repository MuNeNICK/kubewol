# Pre-compile eBPF outside Docker (requires clang + kernel headers on host).
# The compiled .o is embedded via go:embed in internal/ebpf/loader.go.

FROM golang:1.26 AS builder
WORKDIR /workspace
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -o manager ./cmd/

FROM alpine:3.21
RUN apk add --no-cache ca-certificates libcap
# Two copies of the same binary in the image:
#   /manager       → setcap'd for the agent DaemonSet
#   /manager-plain → no file caps, used by the controller Deployment
#
# File caps are needed by the agent: a non-root process that execs a binary
# without file caps loses its effective capability set on exec, even if the
# container runtime attached caps to the pod via SecurityContext.capabilities.
# bpf(BPF_PROG_LOAD) then returns EPERM.
#
# But the controller is unprivileged (NoNewPrivs is implicit when
# allowPrivilegeEscalation=false) and the kernel refuses to exec a binary
# with file capabilities under NoNewPrivs unless those caps are in the
# bounding set. The plain copy sidesteps that by having no file caps at all.
COPY --from=builder /workspace/manager /manager
COPY --from=builder /workspace/manager /manager-plain
RUN setcap cap_bpf,cap_net_admin=eip /manager
USER 65532:65532
ENTRYPOINT ["/manager"]
