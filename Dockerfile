# Pre-compile eBPF outside Docker (requires clang + kernel headers on host).
# The compiled .o is embedded via go:embed in internal/ebpf/loader.go.

FROM golang:1.26 AS builder
WORKDIR /workspace
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/
COPY api/ api/
COPY internal/ internal/
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -o manager ./cmd/

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=builder /workspace/manager /manager
ENTRYPOINT ["/manager"]
