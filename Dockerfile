# Multi-stage build for the tokyo3-ssh-proxy project.
#
# - Stage `builder` compiles both binaries (ssh-proxyd + ssh-tunneld). Building
#   them together amortises `go mod download` across a single cache layer.
#
# - Stage `tunneld` ships only ssh-tunneld. The agent image — runs on every
#   target host that should be reachable via the proxy without inbound port 22.
#
# - Stage `proxy` (default — last stage) ships only ssh-proxyd. The central
#   SSH gateway. Plain `docker build .` produces this image.
#
# Both targets honour TARGETOS / TARGETARCH for cross-builds.

# ── Stage 1: Build Go binaries ────────────────────────────────────────────────
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder

ARG TARGETOS=linux
ARG TARGETARCH=arm64

WORKDIR /src

# Download deps first (cached layer unless go.mod/go.sum change).
COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ cmd/
COPY internal/ internal/

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags="-s -w" -o /out/ssh-proxyd ./cmd/ssh-proxyd
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags="-s -w" -o /out/ssh-tunneld ./cmd/ssh-tunneld

# ── Stage 2: Tunnel agent image (build with --target tunneld) ─────────────────
FROM alpine:3.21 AS tunneld

# tini as PID 1 reaps orphaned children (e.g. ssl_client from busybox-wget
# healthchecks) and forwards signals for clean shutdown — a bare Go PID 1
# doesn't reap, so cgroup pids.current would climb forever.
RUN apk add --no-cache ca-certificates tini

COPY --from=builder /out/ssh-tunneld /usr/local/bin/ssh-tunneld

ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/ssh-tunneld"]
CMD ["run"]

# ── Stage 3: Proxy runtime image (default target) ─────────────────────────────
FROM alpine:3.21 AS proxy

# tini as PID 1 reaps orphaned children (e.g. ssl_client from busybox-wget
# healthchecks) and forwards signals for clean shutdown — a bare Go PID 1
# doesn't reap, so cgroup pids.current would climb forever.
RUN apk add --no-cache ca-certificates tini

COPY --from=builder /out/ssh-proxyd /usr/local/bin/ssh-proxyd

# SSH gateway port — exposed for user clients to connect to.
EXPOSE 2222

ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/ssh-proxyd"]
CMD ["serve"]
