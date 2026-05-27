# tokyo3-ssh-proxy operations runbook

Day-to-day operational guidance for running `ssh-proxyd` and
`ssh-tunneld` in production. Use alongside the per-binary godoc in
`cmd/*/main.go` (the authoritative env-var reference) and
[THREAT_MODEL.md](THREAT_MODEL.md).

## 1. Deployment topology

```
                 user SSH (cert)
            ──────────────────────────►
                                       ┌────────────────┐
                                       │  ssh-proxyd    │
                                       │  :2222 (SSH)   │
                                       │  :2223 (tunnel)│
                                       └───────┬────────┘
                                               │  per-session cert mint
                                               ▼
                                       ┌────────────────┐
                                       │      certd     │
                                       └───────┬────────┘
                                               │  outbound mTLS
                                               │
                                       ┌───────┴────────┐
                                       │   ssh-tunneld  │ (per target host)
                                       │  holds outbound│
                                       │  mTLS+yamux    │
                                       └───────┬────────┘
                                               │  127.0.0.1:22
                                               ▼
                                          local sshd
```

`ssh-proxyd` runs once (or HA'd behind a load balancer) at the
edge. `ssh-tunneld` runs **per target host** that should be
reachable without exposing inbound port 22.

## 2. Initial deploy checklist

### ssh-proxyd

1. **User CA pubkey** (`SSH_PROXYD_USER_CA`) — the public half of
   certd's CA. Workload identity for the proxy must match certd's
   role-table principal so per-session minting works.
2. **TLS material for the inbound tunnel listener:**
   `SSH_PROXYD_TUNNEL_ADDR=:2223`,
   `SSH_PROXYD_TUNNEL_TLS_CERT`/`_KEY` (the proxy server cert
   tunneld trusts),
   `SSH_PROXYD_TUNNEL_CLIENT_CA` (the CA that signs ssh-tunneld
   workload certs).
3. **certd reach-through:** `CERTD_URL` + `CERTD_MTLS_CERT`/`_KEY`/`_CA_BUNDLE`.
4. **Per-session cert TTL:** `CERTD_SESSION_TTL_SECONDS` (default 300).
5. **Recording sink:** `SSH_PROXYD_CAST_DIR` if recording is wanted.
   Without it the proxy still forwards but produces no cast files.
6. **Audit publisher:** `SSH_PROXYD_NATS_URL` + the per-stream TLS
   env vars. Without it audit emission is a no-op.
7. **Revocation polling:** `CERTD_REVOCATIONS_URL` + reuse the
   `CERTD_MTLS_*` material. Without this **revoked certs that are
   otherwise valid will still be accepted** — wire it in production.

### ssh-tunneld (per target host)

1. **Workload mTLS material** the proxy's tunnel listener trusts:
   `SSH_TUNNELD_TLS_CERT`/`_KEY`/`_CA`. The cert's SPIFFE URI must
   look like `spiffe://<td>/host/<fqdn>` — the proxy parses the
   path-tail as the host label for the routing registry.
2. **Proxy address:** `SSH_TUNNELD_PROXY_ADDR`.
3. **Local sshd address:** `SSH_TUNNELD_LOCAL_SSHD` (default 127.0.0.1:22).
4. **Optional host-cert renewal:** `SSH_TUNNELD_HOST_KEY` + `SSH_TUNNELD_CERTD_URL`
   to have tunneld renew the SSH host cert via certd and atomically
   write it next to the on-disk private key.

Start each tunneld and watch for `tunnel connected` + `tunnel
registered` log lines on the proxy side.

## 3. Common scenarios

### Add a new tunnel host

1. On certd: register the workload mTLS principal +
   role (see ca/OPERATIONS.md).
2. Provision the workload cert + key on the target host (via
   `cert-agentd` once an initial cert is in place).
3. Start `ssh-tunneld run` with the env vars from §2.
4. Tail the proxy logs: `tunnel connected target=… remote_addr=…`
   then `tunnel registered hosts=[<fqdn>]`. The new host is now
   reachable as `<user>@<fqdn>` through the proxy.

### Diagnose "user can't connect"

Walk down this list:

1. **Cert validity** — `ssh-keygen -L -f user.cert.pub` shows
   principals, host patterns, `valid before` time. If expired or
   missing the requested principal, the proxy refuses at handshake
   (`user cert rejected` log line).
2. **Cert revocation** — Check certd's `/portal/revocations` for
   the serial. ssh-proxyd's polling cycle is `CERTD_REVOCATIONS_POLL_SECONDS`
   (default 30s); freshly-revoked certs may still validate within
   that window.
3. **RBAC denial** — channel.rejected audit event with stage
   `client_signer` (proxy couldn't mint a session cert from
   certd) or `target_dial` (target unreachable / wrong host key).
4. **Tunnel not registered** — proxy logs include `dialing target
   directly` instead of `dialing target via tunnel`. Either the
   host label doesn't match the SPIFFE URI on tunneld's cert, or
   tunneld is disconnected. Check the proxy's registry via the
   process logs (no portal page for the live registry yet).
5. **Source-address restriction** — cert carries a
   `source-address` critical option; user's IP isn't in any
   listed CIDR. Re-issue the cert with the right range or remove
   the restriction.

### Diagnose "session connected but immediately disconnects"

1. **Target host key mismatch** — `SSH_PROXYD_TARGET_KNOWN_HOSTS`
   pinned an old key. Logs include `ssh handshake to <host>:
   host key mismatch`. Update the known_hosts file.
2. **Target sshd rejected the proxy's per-session cert** — the
   target's `TrustedUserCAKeys` doesn't include certd's CA pubkey,
   or the cert's principal doesn't match a local account. Fix on
   the target sshd, not the proxy.
3. **Recording-disk full** — when `SSH_PROXYD_CAST_DIR` is on a
   full filesystem, `OpenCast` fails. Audit shows
   `recording.completed` never fires; the session itself may
   still work but the channel close path logs warn.

### Recover from a NATS outage

ssh-proxy's audit publish is best-effort. The audit sink uses the
NATS client's async-reconnect (Retry on first failure +
unbounded MaxReconnects + 2s ReconnectWait), so a broker outage
neither blocks ssh-proxyd's startup nor crashes a running gateway —
publish-time failures surface in `audit append failed` logs.
Sessions keep flowing during the outage. After recovery the client
reconnects automatically; there's no restart needed for the audit
pipeline to resume. Note the gap window in certd's `/portal/audit`
for the time range.

### Recover from a certd outage

- **Sign endpoints unavailable** → per-session cert minting fails.
  Existing connections keep working; **new** sessions fail with
  `channel.rejected stage=client_signer`. The minter's failure log
  carries `workload_cert_remaining=<duration>` so the
  certd-client mTLS cert's own exhaustion shows up as a clearly-
  labelled countdown rather than identical-looking error spam.
  Restore certd then no proxy restart needed.
- **Revocations endpoint unavailable** → the polling checker logs
  `revocation refresh failed; keeping previous snapshot` at warn,
  also carrying `workload_cert_remaining=<duration>`. The proxy
  keeps refusing previously-revoked certs but won't pick up new
  revocations until certd is back. Operators should alert on
  `revocation refresh failed` log bursts.
- **Tunnel listener doesn't care** about certd availability —
  tunneld → proxy mTLS handshakes don't go through certd.

At startup, if the loaded certd-client mTLS cert is within 24h of
expiry, ssh-proxyd emits a one-shot warn:
`certd-client mTLS cert near expiry — restart ssh-proxyd after the next rotation`.

### CA-bundle rotation (zero-restart)

ssh-proxyd has two independent TLS surfaces, each with its own
bundle that's mtime-polled every 30s by a dedicated goroutine —
**alongside** the workload cert and tunnel-server cert paths,
so external rotations of any TLS material land in-process on the
next poll without a restart. Operators can drop in a new bundle
on either path; read failures keep the previous pool live and
log warn (`certd-client CA reload failed; …`, `tunnel client CA
reload failed; …`, `certd-client cert reload failed; …`, etc.)
so a corrupt drop-in never opens a trust window.

Every actual swap logs at info — operators rely on these lines
during a coordinated CA rotation to confirm a uniform post-
rotation state across the fleet before flipping certd's signing
key:

  - `certd-client cert reloaded path=… mtime=… not_after=…`
  - `certd-client CA bundle reloaded path=… mtime=… fingerprint=…`
  - `tunnel server cert reloaded path=… mtime=…`
  - `tunnel client CA bundle reloaded path=… mtime=… fingerprint=…`

The fingerprint is `sha256(pem)[:8]` hex — short enough to grep
across a fleet's logs (or NATS-shipped log subjects), long enough
that distinct bundles don't collide in practice.

| Bundle env var                                  | Used for                                              | Pattern                                            |
|-------------------------------------------------|-------------------------------------------------------|----------------------------------------------------|
| `CERTD_CA_BUNDLE`                               | verifying certd's server cert (minter + revchecker)   | InsecureSkipVerify + VerifyConnection              |
| `SSH_PROXYD_TUNNEL_CLIENT_CA` (or `_WORKLOAD_CA`)| verifying inbound ssh-tunneld client certs            | GetConfigForClient → fresh tls.Config per handshake |

The certd-client face uses the same InsecureSkipVerify +
VerifyConnection pattern as cert-agentd / ssh-tunneld so each
handshake reads the *current* pool snapshot. The tunnel-listener
face uses GetConfigForClient (the canonical Go idiom for server-
side hot-reload of ClientCAs) so the standard chain verifier
stays in the path with a freshly-supplied pool per inbound
connection.

Rotation workflow follows the same shape as cert-agentd's:

1. Drop `[OLD, NEW]` bundle on the relevant path. Wait ≥30s +
   safety margin for the poller to fire.
2. Switch certd's signing key from OLD to NEW (still requires a
   certd restart — see ca/OPERATIONS.md §4).
3. Wait for cert-agentd's normal renewal cadence to roll every
   workload onto NEW-signed leafs.
4. Drop `[NEW]` bundle. Trust set narrows back to single-CA on
   the next mtime poll.

### Restart ssh-proxyd

The graceful path drains in-flight sessions before exit. SIGTERM →
the proxy stops accepting new connections + waits for active
sessions to close, capped by the operator-set deadline (default:
process supervisor's grace window).

Recording: in-flight `recording.completed` events fire as each
session ends; the cast file is finalised before the process exits.

### Bring up a new ssh-proxyd instance behind a load balancer

1. New instance comes up with same env vars (including the SAME
   `SSH_PROXYD_HOST_KEY` — different host keys would break user
   known_hosts entries).
2. Tunnels register on whichever proxy they connect to. Today the
   routing registry is **per-process** — a tunnel registered on
   proxy A is invisible to proxy B. For HA you need a shared
   registry (future work) OR a load balancer that pins user
   sessions to the proxy that holds the matching tunnel. Document
   this as the v1 constraint.

### Rotate the proxy's SSH host key

User clients pin the host key via `known_hosts`. Rotating it
breaks every user's first reconnect with "host key changed" until
they accept the new fingerprint.

Recommended approach:
1. Generate the new key + publish its fingerprint via your
   identity portal.
2. Decommission the old key in a maintenance window.
3. Restart ssh-proxyd with `SSH_PROXYD_HOST_KEY` pointing at the
   new key.
4. Users either re-accept on next connect OR pre-distribute the
   new fingerprint via known_hosts2.

## 4. ssh-tunneld operational notes

### What happens when the proxy is unreachable

The dialer logs `tunnel dial failed; backing off` and reconnects
with exponential backoff (1s → 30s, ±20% jitter). The tunnel host
isn't reachable via the proxy during the outage; user sessions
get `target unreachable`. No restart needed once the proxy is back.

Each retry-log line carries `workload_cert_remaining=<duration>` —
the time left on the in-memory workload mTLS cert ssh-tunneld
presents to both the proxy and certd. The cert is loaded once at
startup and is **not** refreshed in-process, so an external
rotation (cert-agentd, manual replace) needs an ssh-tunneld
restart to take effect; until then this duration counts down
toward zero. The same field is appended to the host-cert renewer's
`host cert sign failed; will retry` log line, so a long certd
outage that crosses the cert's expiry surfaces as a clearly-
labelled countdown rather than identical-looking error spam.

At startup, if the loaded workload cert is within 24h of expiry,
the agent emits a one-shot warn:
`workload mTLS cert near expiry — restart ssh-tunneld after the next rotation`.

### CA-bundle rotation (zero-restart)

`SSH_TUNNELD_TLS_CA` (proxy face) and `SSH_TUNNELD_CERTD_CA` (certd
face) are independently mtime-polled every 30s, **alongside** the
workload-cert path (`SSH_TUNNELD_TLS_CERT/_KEY`) — so an external
rotator (cert-agentd, manual replace) lands in-process on the
next poll without a restart. Read failures keep the previous
state live and log warn (`proxy CA reload failed; keeping previous pool`,
`workload cert reload failed; keeping previous cert`, etc.) so a
corrupt drop-in never opens a trust window.

Every actual swap logs at info — operators rely on these lines
during a coordinated CA rotation to confirm a uniform post-rotation
state across the fleet before flipping certd's signing key:

  - `workload cert reloaded path=… mtime=… not_after=…`
  - `proxy CA bundle reloaded path=… mtime=… fingerprint=…`
  - `certd CA bundle reloaded path=… mtime=… fingerprint=…`

The fingerprint is `sha256(pem)[:8]` hex — short enough to grep
across a fleet's logs (or NATS-shipped log subjects), long enough
that distinct bundles don't collide in practice.

The TLS material the agent presents on both faces uses
`InsecureSkipVerify + VerifyConnection` rather than the standard
verifier so each handshake reads the *current* pool snapshot
rather than the one captured at config-construction time;
hostname + chain verification still run inside the callback.

Rotation workflow follows the same shape as cert-agentd:

1. Drop `[OLD, NEW]` bundle on every host (both faces if rotating
   the shared CA; just the relevant face if rotating separately).
   Wait ≥30s + safety margin for every agent's poll to fire.
2. Switch certd's signing key from OLD to NEW (requires a certd
   restart — see ca/OPERATIONS.md §4).
3. Wait for cert-agentd's normal renewal cadence to roll every
   workload onto NEW-signed leafs.
4. Drop `[NEW]` bundle on every host. Trust set narrows back to
   single-CA on the next mtime poll.

### What happens when the local sshd restarts

The forwarder's per-stream dial fails for in-flight streams; those
get closed cleanly. The tunnel session itself stays up (yamux
keepalives still flow). New streams succeed once sshd is listening
again.

### When to restart ssh-tunneld

- Cert renewal exhausted retries (cert about to expire) — restart
  doesn't help, fix certd reachability instead.
- Local sshd address changed — restart with the new
  `SSH_TUNNELD_LOCAL_SSHD`.
- Workload cert expired AND tunneld's renewer never recovered —
  re-provision the cert externally then restart.

## 5. Monitoring hooks

| Probe                                  | What it confirms                                              |
|----------------------------------------|---------------------------------------------------------------|
| ssh-proxyd startup logs                | "user ca ready" / "host key ready" / "listening" all present  |
| NATS subject `ssh.audit.events`        | Tail for every session lifecycle / channel / recording event  |
| ssh-tunneld logs                       | `tunnel connected` / `tunnel session ended; reconnecting`     |
| Cast directory size                    | Grows monotonically; set OS-level quotas before disk full     |
| `revcheck` warn log "refresh failed"   | Burst indicates certd outage or wrong CERTD_REVOCATIONS_URL   |
| portal /audit (in certd)               | Cross-stream view of session opens, channel rejections, etc.  |

## 6. Known limitations

- **Per-process tunnel registry** — no cluster-wide routing for HA
  proxies (see "Bring up a new instance" above).
- **No replay queue** for audit emissions when NATS is down.
- **In-memory recording metadata** — restart drops the ring; query
  JetStream for older sessions.
- **No SCP/SFTP inner-protocol parsing** — `subsystem.opened`
  events log the kickoff but per-file paths aren't captured.
- **Cast disk growth is unbounded** without OS quotas — set them.
