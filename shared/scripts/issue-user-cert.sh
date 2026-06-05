#!/bin/sh
# issue-user-cert.sh — mint a fresh SSH user cert from certd against
# the demo user pubkey staged in shared_data, and write the resulting
# user-cert.pub back to the HOST's ./shared/certs/ so an ssh client
# on the host can pick it up via:
#
#     ssh -i ./shared/certs/user -p 2222 demo@localhost
#
# OpenSSH looks for `<key>-cert.pub` next to `<key>`, so the cert is
# auto-attached.
#
# Run as a one-shot via:
#     docker compose run --rm issue-user-cert
#
# Mounts:
#   /shared:ro       Read-only view of shared_data (ca.crt, ssh-proxyd.crt/key,
#                    user.pub) — the mkcert-signed bootstrap material.
#   /host-certs:rw   Bind mount onto the host's ./shared/certs/ — where the
#                    minted user-cert.pub lands so the host's ssh client
#                    sees it next to user.key.
#
# Auth model: certd is in permissive mode in this rig (no
# CERTD_OIDC_*, no CERTD_MTLS_PRINCIPALS_FILE). The mTLS handshake
# succeeds because ssh-proxyd.crt is signed by mkcert's root (which
# certd accepts at the TLS layer); the sign endpoint then uses
# body-groups for principal resolution and issues the requested cert.
# Production wiring would replace this with the OIDC bearer flow.

set -eu

PRINCIPAL="${PRINCIPAL:-demo}"
KEY_ID="${KEY_ID:-user:${PRINCIPAL}@demo}"
TTL_SECONDS="${TTL_SECONDS:-86400}"

if [ ! -f /shared/certs/user.pub ]; then
  echo "issue-user-cert: /shared/certs/user.pub missing — run 'make gen-certs' on the host first" >&2
  exit 1
fi

# Construct the sign-user request body. The public_key field expects
# the SSH authorized_keys line verbatim (e.g. "ssh-ed25519 AAAA…").
PUBKEY="$(cat /shared/certs/user.pub)"
BODY="$(printf '{
  "public_key": "%s",
  "key_id": "%s",
  "principals": ["%s"],
  "ttl_seconds": %s
}' "$PUBKEY" "$KEY_ID" "$PRINCIPAL" "$TTL_SECONDS")"

echo "issue-user-cert: requesting cert for principal=${PRINCIPAL} key_id=${KEY_ID}"

RESPONSE="$(curl -sS \
  --cacert /shared/certs/ca.crt \
  --cert   /shared/certs/ssh-proxyd.crt \
  --key    /shared/certs/ssh-proxyd.key \
  -H 'Content-Type: application/json' \
  -d "$BODY" \
  "https://certd:8443/api/v1/ssh/sign-user")"

# Extract the "certificate" field from the JSON response. Avoid
# pulling jq just for this — the field is a one-line string and the
# response shape is fixed.
CERT="$(printf '%s' "$RESPONSE" | sed -n 's/.*"certificate":"\([^"]*\)".*/\1/p')"
if [ -z "$CERT" ]; then
  echo "issue-user-cert: certd response missing 'certificate' field:" >&2
  echo "$RESPONSE" >&2
  exit 1
fi

# Write to /host-certs (bind-mounted ./shared/certs on host) so the
# host's ssh client sees user-cert.pub next to user.key.
printf '%s\n' "$CERT" > /host-certs/user-cert.pub
chmod 644 /host-certs/user-cert.pub
echo "issue-user-cert: wrote ./shared/certs/user-cert.pub on host"
echo "issue-user-cert: cert details:"
ssh-keygen -L -f /host-certs/user-cert.pub 2>/dev/null || true
