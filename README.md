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

**Scaffold only.** Binaries compile and respond to `version` / `--help` but
`ssh-proxyd serve` and `ssh-tunneld run` subcommands are not yet implemented.

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
