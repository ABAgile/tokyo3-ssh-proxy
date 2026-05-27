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

**Production-shape, with the documented caveats.** `ssh-proxyd
serve` is a full SSH gateway: cert-based user auth, source-address
restrictions, per-session cert minting from certd, asciinema
recording, port-forward + SCP/SFTP-kickoff audit, inbound tunnel
acceptance, and revocation polling against certd's snapshot.
`ssh-tunneld run` is a full reverse-tunnel agent: outbound
mTLS+yamux to ssh-proxyd, forwards inbound streams to local sshd,
and renews its host SSH cert via certd when configured.

Phase 7 hardening landed:
[THREAT_MODEL.md](THREAT_MODEL.md) (per-surface threats +
mitigations), [OPERATIONS.md](OPERATIONS.md) (deploy/scenario
runbooks), benchmark suite (`go test -bench=. -benchmem ./...`),
PTY recording stress tests, and an end-to-end revocation test
that proves the certd→proxy refusal loop closes through the
handshake layer.

Operational caveats are tracked in [OPERATIONS.md §6](OPERATIONS.md):
per-process tunnel registry (no cluster-wide routing yet),
audit-publish loss tolerance during NATS outage, unbounded cast
disk without OS quotas, and SCP/SFTP audit only captures the
kickoff (no per-file paths).

See the `go doc` comments in `cmd/ssh-proxyd/main.go` and
`cmd/ssh-tunneld/main.go` for the full env-var matrix.

## User access

End users don't talk to ssh-proxyd directly with `ssh -J`; they use
`auth-ssh-creds` to exchange an SSO ID token for a short-lived SSH
user certificate, which `ssh` then presents at the gateway. The
helper also emits an `ssh_config` snippet pointing at this proxy
when invoked with `--proxy-jump <ssh-proxyd-host:port>`, so a single
`ssh <target>` routes through here transparently.

The helper lives in [tokyo3-ca](https://github.com/abagile/tokyo3-ca)
because its wire shape tracks certd's `/api/v1/ssh/sign-user`
endpoint — install it with:

```sh
go install github.com/abagile/tokyo3-ca/cmd/auth-ssh-creds@latest
```

Or pull the published image: `ghcr.io/abagile/tokyo3-ca-cli`. See
the [tokyo3-ca README](https://github.com/abagile/tokyo3-ca#cli-access-via-auth-ssh-creds)
for full flag reference, cache layout, and the `--proxy-jump` workflow.

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

Benchmarks for the per-handshake hot paths (`rbac` extension checks,
`routing.Registry` lookups, `revcheck.IsRevoked`, audit serialization):

```sh
go test -bench=. -benchmem -run=^$ ./internal/proxyd/rbac/...
go test -bench=. -benchmem -run=^$ ./internal/proxyd/routing/...
go test -bench=. -benchmem -run=^$ ./internal/proxyd/revcheck/...
go test -bench=. -benchmem -run=^$ ./internal/audit/...
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
- **Revocation gating.** When `CERTD_REVOCATIONS_URL` is set, ssh-proxyd
  polls certd's snapshot every `CERTD_REVOCATIONS_POLL_SECONDS` (default
  30s) into an in-memory map keyed by serial + KeyID. The SSH server's
  `gossh.CertChecker.IsRevoked` callback consults the map at every
  handshake — revoked certs are refused before they reach the channel
  router. Fetch failures keep the previous snapshot live so a transient
  certd outage doesn't suddenly admit previously-revoked certs.
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
| `port_forward.opened`  | After a `direct-tcpip` channel is accepted (src/dst host:port).|
| `port_forward.closed`  | When the `direct-tcpip` channel ends (bytes_in/out, duration). |
| `subsystem.opened`     | When a session starts SCP (exec `scp …`) or SFTP (subsystem).  |

`recording.completed` carries the absolute cast path and metadata with
`duration_seconds` and `started_at`. Audit emission is best-effort —
failures are logged but never block the wire.

NATS connection is configured via `SSH_PROXYD_NATS_URL`,
`SSH_PROXYD_NATS_CERT`, `SSH_PROXYD_NATS_KEY`, and
`SSH_PROXYD_NATS_CA` (falling back to `SSH_PROXYD_WORKLOAD_CA`). When
unset, audit emission silently degrades to a no-op sink.

## Operational log shipping

Both binaries ship structured log lines to NATS (alongside stdout)
when their `*_NATS_URL` env var is set; unset leaves the logger at
stdout only. Subject layout depends on whether the daemon is a
cluster-wide singleton or runs on every workload host:

| Binary         | Subject                                | Env-var prefix       | `Instance` source                                       |
|----------------|----------------------------------------|----------------------|----------------------------------------------------------|
| `ssh-proxyd`   | `app_log.ssh-proxyd`                   | `SSH_PROXYD_NATS_*`  | n/a — singleton                                          |
| `ssh-tunneld`  | `app_log.ssh-tunneld.<instance>`       | `SSH_TUNNELD_NATS_*` | `SSH_TUNNELD_INSTANCE` (default `os.Hostname()`)        |

Operators can tail per-host with `nats sub 'app_log.ssh-tunneld.host-42'`
or fleet-wide with `nats sub 'app_log.ssh-tunneld.>'`. Every log
line on the per-host subject also carries a matching `"instance"`
slog attribute so attribute-based consumers can filter without
parsing subjects.

ssh-proxyd reuses its existing `SSH_PROXYD_NATS_*` audit env vars
(one broker, two subjects). ssh-tunneld's NATS cert / key / CA
each fall back to the workload-identity material it already uses
for the proxy tunnel (`SSH_TUNNELD_TLS_CERT/_KEY/_CA`), so a single
TLS file set covers both the tunnel connection and log shipping.

The shipper dials with `RetryOnFailedConnect(true)` and unbounded
reconnects — a broker that's down at boot doesn't fail process
startup; entries drop (200-entry discard-on-full buffer) while
disconnected and resume on reconnect. See the per-binary godoc in
[`cmd/ssh-proxyd/main.go`](cmd/ssh-proxyd/main.go) and
[`cmd/ssh-tunneld/main.go`](cmd/ssh-tunneld/main.go) for the
authoritative env-var reference.

## Operations

See [OPERATIONS.md](OPERATIONS.md) for deployment topology, the
initial-deploy checklist, scenario playbooks (add a tunnel host,
diagnose stuck sessions, recover from certd / NATS outage, rotate
the proxy host key), ssh-tunneld lifecycle notes, and monitoring
hooks.

## Security

See [THREAT_MODEL.md](THREAT_MODEL.md) for the per-surface threat
inventory + mitigations. Reviewers should walk the document's
checklist when auditing changes that touch the SSH handshake path,
channel proxying, the tunnel listener, or audit emissions.

## License

See [LICENSE](LICENSE).
