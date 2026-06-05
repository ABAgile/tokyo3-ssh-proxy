# Target sshd for the local-test rig — a minimal alpine container
# running openssh-server, configured to trust certd's user-CA pubkey
# via TrustedUserCAKeys. The "demo" user is the principal a user cert
# needs to authorise — match it in the cert request (principals=["demo"]).
#
# Used by ssh-proxy/docker-compose.yml as the SSH endpoint that
# ssh-tunneld forwards into. Not a published image.

FROM alpine:3.21

RUN apk add --no-cache openssh-server && \
    adduser -D -s /bin/sh demo && \
    passwd -u demo && \
    ssh-keygen -A

# TrustedUserCAKeys reads certd's user-CA pubkey straight from the
# shared_data volume mounted read-only at /shared (certd-signing.key.pub,
# the file `ssh-keygen -f certd-signing.key` emits). PermitRootLogin and
# password auth are disabled — cert-only access via the trusted user CA
# is the entire point of this demo.
RUN cat >> /etc/ssh/sshd_config <<'EOF'

# tokyo3 dev rig — cert-only auth via certd's user CA
TrustedUserCAKeys /shared/certs/certd-signing.key.pub
PubkeyAuthentication yes
PasswordAuthentication no
ChallengeResponseAuthentication no
PermitRootLogin no
LogLevel VERBOSE
EOF

EXPOSE 22

# -D foreground, -e log to stderr (compose picks it up via `docker compose logs`)
CMD ["/usr/sbin/sshd", "-D", "-e"]
