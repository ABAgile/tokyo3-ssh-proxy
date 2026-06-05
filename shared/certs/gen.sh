#!/usr/bin/env bash
# Generate dev TLS material + SSH keys for the docker-compose rig,
# signed by mkcert's local root CA. Run on the HOST from the repo root:
#
#     make gen-certs
#     # or: bash shared/certs/gen.sh
#
# Material lands next to this script under shared/certs/. `make
# _sync-shared` tar-pipes the directory into the shared_data named
# volume, so containers see it at /shared/certs/. `issue-user-cert`
# additionally bind-mounts ./shared/certs onto /host-certs so the
# minted user-cert.pub lands on the host next to user.key (for
# `ssh -i ./shared/certs/user`).
#
# Requires:
#   - mkcert (auto-installed via `go install` if missing — Go env must
#     already be set up so the mkcert binary lands on PATH)
#   - ssh-keygen (any OpenSSH install)
#
# Uses the abagile/mkcert fork (https://github.com/abagile/mkcert@add-cn)
# so the first hostname argument becomes Subject CN.
#
# `mkcert -install` adds the local root CA to the OS + browser trust
# stores on first run. The compose rig's certd then serves a cert that
# both the host (curl, browser) AND the in-network containers trust
# (the same rootCA.pem is copied to ./certs/ca.crt for container use).
#
# Idempotent: re-runs regenerate leaf certs in place. Signing keys
# (certd-signing.key + .pub, user.key + .pub) are only generated when
# missing — rotating them would invalidate every cert + cached
# known_hosts entry that referenced them, rarely what you want for a
# dev rig.

set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="$DIR"
mkdir -p "$OUT"

step() { printf '  %-34s' "$1..."; }
ok()   { echo "ok"; }
skip() { echo "skip ($1)"; }

# ── Ensure mkcert (abagile fork) is available ────────────────────────────────
if ! command -v mkcert >/dev/null 2>&1; then
  step "installing mkcert"
  go install github.com/abagile/mkcert@add-cn >/dev/null
  ok
fi

step "mkcert -install"
mkcert -install >/dev/null 2>&1
ok

CAROOT="$(mkcert -CAROOT)"

# ── Root CA bundle (stable filename for containers) ──────────────────────────
step "ca.crt (mkcert root)"
cp "$CAROOT/rootCA.pem" "$OUT/ca.crt"
ok

# ── Helpers ──────────────────────────────────────────────────────────────────
mkc_server() {
  local name=$1; shift
  step "$name (server cert)"
  mkcert -cert-file "$OUT/$name.crt" -key-file "$OUT/$name.key" "$@" >/dev/null 2>&1
  ok
}

mkc_client() {
  local name=$1; shift
  step "$name (client cert)"
  mkcert -client -cert-file "$OUT/$name.crt" -key-file "$OUT/$name.key" "$@" >/dev/null 2>&1
  ok
}

# ── X.509 leaf certs ─────────────────────────────────────────────────────────
# certd HTTPS server cert. SANs cover both in-network (certd) and
# host-side (localhost / 127.0.0.1) access.
mkc_server "certd"          certd  localhost  127.0.0.1

# ssh-proxyd's tunnel-listener cert. ssh-tunneld dials in over mTLS
# and verifies the SNI against this cert.
mkc_server "tunnel-server"  ssh-proxyd  proxy.internal  127.0.0.1

# Workload client certs.
#
# mkcert's leaf CSRs include a SPIFFE URI SAN when any argument starts
# with "spiffe://". The fork preserves the URI through to the X.509
# extension.
mkc_client "ssh-proxyd"     spiffe://demo/svc/ssh-proxyd  ssh-proxyd
mkc_client "ssh-tunneld"    spiffe://demo/host/target     ssh-tunneld  target

# ── certd's SSH user CA + demo user keypair ──────────────────────────────────
# certd-signing is the user CA: the target sshd pins certd-signing.key.pub
# via TrustedUserCAKeys. Generated once; rotating it invalidates every
# user cert ever issued, which is rarely what you want for a dev rig.
if [[ ! -f "$OUT/certd-signing.key" ]]; then
  step "certd-signing (user CA)"
  ssh-keygen -t ed25519 -f "$OUT/certd-signing.key" -C certd-user-ca -N "" >/dev/null
  ok
else
  step "certd-signing"
  skip "exists — delete certd-signing.key to rotate"
fi

# The demo user's keypair. `docker compose run --rm issue-user-cert`
# mints a cert against user.pub and writes it to user-cert.pub on the
# host (via the bind mount), so ssh picks it up automatically when
# invoked with `-i ./shared/certs/user`.
if [[ ! -f "$OUT/user" ]]; then
  step "user (demo SSH keypair)"
  ssh-keygen -t ed25519 -N "" -C "demo-user@tokyo3" -f "$OUT/user" >/dev/null
  ok
else
  step "user"
  skip "exists — delete user/user.pub to rotate"
fi

echo ""
echo "dev TLS material + SSH keys written to ./shared/certs/"
echo "CA: $CAROOT/rootCA.pem (mkcert root, trusted via mkcert -install)"
echo "next: make docker-up    # _sync-shared tar-pipes ./shared/ + brings up the rig"
