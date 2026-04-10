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
COPY --from=builder /workspace/manager /manager
# Grant the file caps needed for eBPF load + TC attach directly on the
# binary so the process keeps them across exec when running as a non-root
# UID (runAsUser: 65532). Without file caps, a non-root exec clears the
# effective set even if SecurityContext.capabilities.add lists them, and
# bpf(BPF_PROG_LOAD) returns EPERM.
RUN setcap cap_bpf,cap_net_admin=eip /manager
# Run as the nonroot UID provided by distroless / nobody in alpine.
USER 65532:65532
ENTRYPOINT ["/manager"]
