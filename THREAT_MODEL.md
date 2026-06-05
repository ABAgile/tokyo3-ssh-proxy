# tokyo3-ssh-proxy threat model

This document captures the trust boundaries, attack surfaces, and
mitigations for `ssh-proxyd` and `ssh-tunneld`. It exists so a
reviewer can audit each mitigation against the corresponding source
rather than re-deriving it from code comments.

Scope: code in this repository. Out of scope: certd (separate
threat model), the NATS broker, target sshds, and the operator's
identity infrastructure.

## Components and trust boundaries

```
                        ┌──────────────────────────────────────┐
   user SSH (cert)      │            ssh-proxyd                │
  ─────────────────────►│  ┌─────────────────────────────┐     │
                        │  │  SSH server (gossh)         │     │
                        │  │  CertChecker + RBAC         │     │
                        │  └────────┬────────────────────┘     │
                        │           │                          │
                        │   ┌───────▼────────┐                 │
                        │   │  session       │   recording     │
                        │   │  Proxier       │──► local FS / S3│
                        │   │  audit emit    │──► NATS         │
                        │   └───────┬────────┘                 │
                        │           │                          │
                        │    direct TCP OR yamux stream        │
                        │           │                          │
                        └───────────┼──────────────────────────┘
                                    ▼
                          target sshd (port 22)
                          OR
                  ┌─────────────────┐         ┌──────────────┐
                  │  routing tunnel │◄────────┤ ssh-tunneld  │
                  │  (mTLS + yamux) │         │  on target   │
                  └─────────────────┘         └──────────────┘
                  ssh-proxyd "tunnel listener"
                                ▲
                                │ mTLS workload identity
                                │
                       ┌────────────────────┐
                       │  ssh-tunneld       │
                       │ (per-host agent)   │
                       └────────────────────┘
```

Trust boundaries:

| Boundary               | Direction               | Mechanism                                          |
|------------------------|-------------------------|----------------------------------------------------|
| User → ssh-proxyd      | Inbound SSH             | gossh cert auth (CA-signed, principals, RBAC)      |
| ssh-proxyd → target    | Outbound SSH            | gossh client cert (per-session, minted by certd)   |
| ssh-tunneld → proxy    | Outbound mTLS+yamux     | SPIFFE workload cert                               |
| ssh-proxyd → certd     | HTTPS mTLS              | Workload identity → certd's role table             |
| ssh-tunneld → certd    | HTTPS mTLS              | Workload identity → host-cert role                 |
| ssh-proxyd → NATS      | mTLS publish            | Workload identity → publisher role                 |
| Recording → disk       | Filesystem              | File-mode 0600 cast files (audit data)             |
| User → portal HTTP     | Inbound HTTP            | Optional Basic auth; read-only session list + casts |

## Surfaces and threats

### S1. User-facing SSH server at `:2222`
**Surface:** `gossh.Server` accepting inbound SSH connections.

Threats:

| # | Threat                                                                       | Mitigation                                                                                                                                                                                                       |
|---|------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1 | Anonymous user opens a session                                               | `pssh.Server.publicKeyCallback` (`internal/proxyd/ssh/server.go`) requires a User certificate signed by the configured `TrustedUserCA`. Non-certs are refused.                                                    |
| 2 | Expired or revoked cert opens a session                                      | `gossh.CertChecker` validates the cert's NotBefore/NotAfter envelope. `IsRevoked` callback checks `Revocations.IsRevoked` (when wired); ssh-proxyd's `revcheck.PollingChecker` keeps the set fresh from certd.    |
| 3 | Cert from a different CA accepted                                            | `IsUserAuthority` compares the cert's signing key against `TrustedUserCA.Marshal()`. Test `TestServer_RejectsCertFromWrongCA` pins this.                                                                          |
| 4 | Source-address restriction bypass                                            | `rbac.CertEnforcer.SourceAddressOK` (`internal/proxyd/rbac`) parses the cert's `source-address` critical option and matches against `meta.RemoteAddr`. Handshake fails if the address is out of range.            |
| 5 | Principal escalation                                                         | `gossh.CertChecker.CheckCert(remoteUser, cert)` requires the remote user (parsed from `meta.User()`) to appear in `cert.ValidPrincipals`. Test `TestServer_RejectsPrincipalMismatch` pins this.                  |
| 6 | RBAC bypass on channels                                                      | `Proxier.handleChannel` (`internal/proxyd/session/proxy.go`) consults `rbac.PermitsPortForwarding` and gates `direct-tcpip` channels. Other channel types currently inherit pass-through behaviour.               |
| 7 | Slow-loris on handshake                                                      | `Config.HandshakeTimeout` (default 30s) caps the time a single inbound connection can occupy a handshake goroutine.                                                                                                |
| 8 | Username injection via SSH user field                                        | `session.ParseTarget` validates the `<remote-user>@<host>` shape and rejects whitespace/special-char abuse.                                                                                                       |

### S2. Outbound dial to the target
**Surface:** `session.DialTarget` opening an SSH client connection
to the target sshd.

Threats:

| # | Threat                                                       | Mitigation                                                                                                                                                                                                       |
|---|--------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1 | MITM on target sshd                                          | `TargetHostKeyCallback` is mandatory. Production wires a `known_hosts` callback (or a CA-trust check once host certs are universal); dev paths log a warning when `InsecureIgnoreHostKey` is in use.              |
| 2 | Per-session cert leakage                                     | `cmd/ssh-proxyd/main.go::newCertdMinter` generates a fresh ed25519 keypair per session; the private key never persists. The KeyID embeds the session UUID + principal for audit attribution.                     |
| 3 | Dial timeout escalation                                      | `DialConfig.Timeout` caps both the TCP connect and the SSH handshake. Defaults to 15s.                                                                                                                            |
| 4 | Tunnel registry abuse                                        | `tunnelTransport` consults `routing.Registry`; the host label key is derived from the cert SAN by the listener, not user-controllable. See S4 below.                                                              |

### S3. Channel proxying + recording
**Surface:** `Proxier.pipeChannel`, `channelRecorder`,
`recording.LocalDirSink`.

Threats:

| # | Threat                                                  | Mitigation                                                                                                                                                                                                       |
|---|---------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1 | Recording bypass                                        | When `RecordingSink` is wired, every session channel gets a `channelRecorder` (`session/recorder.go`). The recorder is keyed off the channel type ("session") so non-PTY exec sessions don't bloat the disk.    |
| 2 | Path traversal in cast filenames                        | `LocalDirSink.OpenCast` (`recording/sink.go`) sanitizes SessionID with `filepath.Clean` + checks for path separators. `O_EXCL` opens prevent overwriting an existing record.                                     |
| 3 | Cast file disclosure                                    | Cast files land at mode 0600 (owner-only read). The portal serves them only through `LocalCastStore.Open` which re-enforces the root prefix.                                                                     |
| 4 | Out-of-band audit-event injection via recording metadata | `recording.completed` event metadata is serialised from typed fields (SessionID, duration). User input never lands directly in the audit payload.                                                                  |
| 5 | Resource exhaustion via giant PTY output                | No per-session cast-size cap currently implemented. Operators set disk quotas on `SSH_PROXYD_CAST_DIR`. Documented residual risk.                                                                                |
| 6 | Subsystem-detection false negatives                     | `detectSubsystem` (`session/subsystem.go`) matches `scp` by command prefix + `sftp` by subsystem name. Operators who alias or rename binaries on the target bypass the audit attribution — accepted residual.    |
| 7 | Port-forward byte-count underflow                       | `countingChannel` (`session/portforward.go`) uses `atomic.AddInt64`. The closure-form defer captures counters AFTER the pipe runs.                                                                                |

### S4. Reverse-tunnel listener at `:2223`
**Surface:** `routing.Listener` accepting inbound mTLS+yamux from
`ssh-tunneld` agents.

Threats:

| # | Threat                                                  | Mitigation                                                                                                                                                                                                       |
|---|---------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1 | Anonymous host registers as `db-1.prod`                 | `tls.Config.ClientAuth = RequireAndVerifyClientCert` + `ClientCAs`. The listener parses the SPIFFE URI from the peer cert and uses its path-tail as the host label — the host *cannot* claim a label outside its cert. |
| 2 | Host registers under a label its cert doesn't authorise | `HostFromSPIFFE` (`routing/listener.go`) requires the URI path to start with `/host/` and uses the remainder verbatim. A cert with `spiffe://td/workload/x` is refused.                                            |
| 3 | Stale tunnel keeps serving after the agent dies         | yamux keepalives (15s interval, 30s frame timeout) detect dead links. `Registry.Lookup` scrubs `IsClosed` sessions on each lookup. `Register` evicts dead-entry collisions so reconnect-faster-than-Unregister works.|
| 4 | Tunnel impersonation via reused cert                    | mTLS + yamux session lifecycle is per-TCP-connection. A new tunnel from the same cert registers a new session pointer; the old one's CloseChan fires on TCP teardown.                                            |

### S5. ssh-tunneld
**Surface:** Outbound dial to ssh-proxyd; local sshd accept loop;
host cert renewal calls to certd.

Threats:

| # | Threat                                          | Mitigation                                                                                                                                                                                          |
|---|-------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1 | tunneld talks to a rogue proxy                  | The dialer's `tls.Config.RootCAs` pins the CA that signs ssh-proxyd's server cert. `ServerName` is set explicitly.                                                                                  |
| 2 | Local sshd address spoofing                     | `forward.Forwarder.LocalAddr` is operator-configured (default 127.0.0.1:22). The forwarder dials this address only — never an attacker-controlled address from the stream payload.                  |
| 3 | Host cert key disclosure                        | The host cert key is the existing sshd host key (never touched by tunneld). tunneld only reads its public half to submit to certd.                                                                  |
| 4 | Renewer hammering certd on bad config           | `hostcert.Renewer.RetryBackoff` (default 30s) + `MinRenewInterval` (1 min) cap the retry rate.                                                                                                      |
| 5 | Backoff DoS during certd outage                 | Dialer + renewer keep retrying with exponential backoff capped at MaxBackoff (30s). On certd recovery the next renewal lands within at most that window.                                            |

### S6. Audit publish
**Surface:** NATS JetStream stream `ssh_audit` with subject
`ssh.audit.events`.

Threats:

| # | Threat                                          | Mitigation                                                                                                                                                                                          |
|---|-------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1 | Forged audit entries                            | Publishes are over mTLS to the broker. Brokers must reject unauthenticated publishes (operator-configured ACL).                                                                                     |
| 2 | Sensitive data in audit payload                 | `audit.Entry` fields are typed; metadata is JSON-encoded explicitly per event. No raw key material is ever placed in `Metadata` (review checklist below).                                           |
| 3 | Audit-publish failure masks a breach            | Failures are logged at warn but never block the wire — accepted because a recording session must complete cleanly. Operators alert on broker unavailability.                                        |

### S7. Admin portal HTTP surface
**Surface:** Optional read-only web UI on `SSH_PROXYD_PORTAL_ADDR`
(`internal/proxyd/portal`) — recorded-session list + asciinema cast
replay, plus an `/audit` viewer tailing the `ssh_audit` stream.
ssh-proxyd's only HTTP listener; unset ⇒ not started. All routes are
GET (read-only) and share the same Basic-auth gate + `html/template`
escaping covered below.

Threats:

| # | Threat                                                  | Mitigation                                                                                                                                                                                          |
|---|---------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1 | Anonymous access to session recordings                  | Optional HTTP Basic gate (`requireBasicAuth`, `portal/auth.go`): active when `SSH_PROXYD_PORTAL_USERNAME` + `_PASSWORD` are set, constant-time compared. When unset the portal is open by design — operators MUST front it with an identity-aware edge and keep it off the public internet. `/healthz` is exempt. |
| 2 | Path traversal serving arbitrary files via a hostile `recording_path` | `LocalCastStore.Open` (`portal/cast.go`) resolves the requested path through `filepath.EvalSymlinks` and refuses anything outside `SSH_PROXYD_CAST_DIR` with `ErrCastOutsideRoot` → HTTP 403. Tests `TestLocalCastStore_RejectsTraversal` / `_RejectsPathOutsideRoot` pin the guard. |
| 3 | XSS via session metadata rendered in HTML               | Pages render through `html/template`, which context-escapes every interpolated value (user, target, principals, recording path — all sourced from cert KeyIDs + audit events).                       |
| 4 | CSRF / state mutation                                   | The portal is read-only — every route is `GET` and nothing mutates server state — so there is no CSRF surface.                                                                                       |
| 5 | Slow-loris / header DoS on the listener                 | `http.Server.ReadHeaderTimeout` (10s) caps how long a single connection can occupy a request goroutine before headers are read.                                                                     |



1. **No per-session disk-size cap** on cast files. Set OS quotas.
2. **Subsystem detection** is exec/payload-prefix based — operator-renamed binaries bypass it.
3. **No rate limiting on inbound SSH** — front the proxy with an edge load balancer that does it.
4. **Tunnel listener accepts any cert signed by the configured CA** with a `/host/<label>` SPIFFE URI. Per-host signing-time controls live in certd's role table; the proxy trusts certd's gating.
5. **Audit data loss tolerance** by design.
6. **TARGET HOST KEY VERIFICATION** has a dev fallback (`InsecureIgnoreHostKey`). Production must wire `SSH_PROXYD_TARGET_KNOWN_HOSTS`.

## Out-of-scope assumptions

- gossh and yamux are correct. Trusted; their security advisories
  drive govulncheck integration.
- The OS kernel correctly enforces file modes / mlocks. Trusted.
- The NATS broker enforces its own ACLs. Trusted.
- The CA the proxy trusts is operated correctly (see the tokyo3-ca
  threat model).

## Review checklist

When reviewing ssh-proxy changes, walk through:

1. Does it touch the SSH handshake path? Confirm `gossh.CertChecker` runs first; revocation + RBAC gates still fire.
2. Does it open a new channel type? Add an RBAC gate in `Proxier.handleChannel`; emit a `channel.*` audit event.
3. Does it touch the recording path? Confirm cast files land at mode 0600 and the sink is `O_EXCL`.
4. Does it touch the tunnel listener? Confirm `HostFromSPIFFE` is used (or a tested equivalent); operators don't lose audit attribution.
5. Does it add audit events? Add the new Action constant to `internal/audit/audit.go` AND surface it in this document.
6. Does it add an env var? Document in `cmd/ssh-proxyd/main.go` (or `cmd/ssh-tunneld/main.go`) AND in README.
7. Does it touch the admin portal? Keep routes read-only (GET); render through `html/template`; serve casts only via `LocalCastStore.Open` (root-prefix guard); confirm the Basic-auth gate still wraps every non-`/healthz` route.
