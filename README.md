# tokyo3-ssh-proxy

SSH gateway and reverse-tunnel transport for the tokyo3 platform. Provides
human and workload access to internal hosts without exposing port 22 on any
target. Validates short-lived certificates issued by `tokyo3-ca`, records
sessions for replay, and routes traffic over multiplexed reverse tunnels
established from each host.

This repo ships two binaries:

| Binary        | Role                                                                                                                  |
|---------------|-----------------------------------------------------------------------------------------------------------------------|
| `ssh-proxyd`  | Central SSH gateway. Terminates user SSH, mints per-session certs from certd, records PTY to S3, routes via tunnels.  |
| `ssh-tunneld` | Per-host reverse-tunnel agent. Renews host cert from certd, dials the proxy, forwards inbound streams to local sshd.  |

## Status

**MVP wired end-to-end.** `ssh-proxyd serve` is a full SSH gateway with
cert-based user auth, per-session cert minting from certd, asciinema
recording, audit emission, and (optional) inbound tunnel acceptance.
`ssh-tunneld run` is a full reverse-tunnel agent: holds an outbound
mTLS+yamux session to ssh-proxyd, forwards inbound streams to local
sshd, and renews its host SSH cert when configured.

See the `go doc` comments in `cmd/ssh-proxyd/main.go` and
`cmd/ssh-tunneld/main.go` for the full env-var matrix. The
`SSH_PROXYD_TUNNEL_*` and `SSH_TUNNELD_*` variables wire the
reverse-tunnel path; without them the proxy still works in
direct-TCP mode.

## Requirements

- Go 1.26.3+
- A running `tokyo3-ca` instance (certd) reachable over mTLS
- An OIDC IdP (`tokyo3-auth` / authd) for user authentication
- S3 (or compatible) for recording storage
- NATS JetStream (audit pipeline) — optional, gracefully degrades when absent

## Build

```sh
make build         # → bin/ssh-proxyd + bin/ssh-tunneld
make check         # gofmt + test + staticcheck + gopls + govulncheck
```

## Layout

```
cmd/
  ssh-proxyd/main.go         # central SSH gateway entry point
  ssh-tunneld/main.go        # per-host reverse-tunnel agent entry point
internal/
  proxyd/                    # ssh-proxyd only
    ssh/                     # SSH protocol terminator
    session/                 # session lifecycle
    recording/               # PTY mirror → asciinema → S3
    routing/                 # tunnel registry, stream router
    rbac/                    # cert-extension enforcement at session time
  tunneld/                   # ssh-tunneld only
    tunnel/                  # outbound yamux client
    forward/                 # stream → 127.0.0.1:22 forwarder
    hostcert/                # host cert renewal
  common/                    # shared between the two binaries
    tunnel/                  # mux primitives, framing
    certclient/              # wrapper around tokyo3-ca/internal/client
```

## Design

- **No inbound port 22 on targets.** ssh-tunneld holds an outbound
  multiplexed connection to ssh-proxyd; new sessions ride that tunnel.
- **Proxy-terminated SSH.** ssh-proxyd is a real SSH server to the user
  and a real SSH client to the target's local sshd, which is what enables
  PTY recording. The reverse tunnel is pure transport underneath.
- **The cert is the authorization token.** ssh-proxyd has no policy DB —
  it enforces what the user cert says (allowed-principals, host-pattern
  extension), which certd embedded at sign time per the role table.
- **ssh-tunneld owns its host identity.** Each tunnel agent renews its
  own SSH host certificate from certd over its existing workload mTLS
  identity (no shared bootstrap key). The fresh cert is written
  atomically to `/etc/ssh/ssh_host_*-cert.pub` and an `OnRenewed` hook
  notifies sshd (typically SIGHUP). Renewal fires at 60% of the
  validity envelope by default; signing failures retry without
  disrupting sshd, which keeps serving with the existing cert until
  it expires.
- **Mux is yamux over mTLS.** ssh-tunneld holds an outbound,
  long-lived mTLS connection to ssh-proxyd, wrapped in a
  [yamux](https://github.com/hashicorp/yamux) session. Both sides
  share `internal/common/tunnel` config (15s keepalive, 30s frame
  timeout, 4 MiB per-stream window) so drift is impossible. The
  dialer reconnects with exponential backoff (1s → 30s, ±20% jitter)
  on session loss and surfaces the live session to a caller-supplied
  `SessionHandler` for stream forwarding.
- **Per-stream forwarding to local sshd.** `internal/tunneld/forward`
  is the canonical `SessionHandler`: it loops on `AcceptStream`,
  dials the configured local addr (default `127.0.0.1:22`) for each
  stream, and pipes bytes both ways. A failed dial closes only that
  stream — the session keeps serving subsequent streams, so an sshd
  restart doesn't take the whole tunnel down.
- **Routing decisions are credential-driven, not topology-driven.**
  ssh-proxyd holds a `routing.Registry` (case-folded host label →
  live yamux session). `session.DialTarget` accepts a pluggable
  `Transport` hook so the proxy substitutes a `registry.Open`-backed
  dial for tunneled hosts while keeping direct TCP for everything
  else. A dead session (yamux `IsClosed`) is scrubbed lazily on the
  next lookup so a flaky agent doesn't strand stale tunnels in the
  registry.

## Audit events

ssh-proxyd publishes per-session events to NATS JetStream on subject
`ssh.audit.events` (stream `ssh_audit`, retained 400 days). Each event is
keyed by a per-connection `session_id` so lifecycle and recording events
can be correlated.

| Action                 | Emitted when                                                  |
|------------------------|---------------------------------------------------------------|
| `session.opened`       | After SSH handshake + cert validation succeed.                |
| `session.closed`       | When the SSH connection ends (success or error).              |
| `channel.rejected`     | When a channel-open request is denied by RBAC or routing.     |
| `recording.completed`  | When a PTY session's asciinema cast file has been finalised.  |

`recording.completed` carries the absolute cast path and metadata with
`duration_seconds` and `started_at`. Audit emission is best-effort —
failures are logged but never block the wire.

NATS connection is configured via `SSH_PROXYD_NATS_URL`,
`SSH_PROXYD_NATS_CERT`, `SSH_PROXYD_NATS_KEY`, and
`SSH_PROXYD_NATS_CA` (falling back to `SSH_PROXYD_WORKLOAD_CA`). When
unset, audit emission silently degrades to a no-op sink.

## License

See [LICENSE](LICENSE).
