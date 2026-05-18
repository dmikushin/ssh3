#!/usr/bin/env bash
# Server entrypoint.  Idempotent: safe to restart.
#
# Env vars (with defaults):
#   SSH3_BIND           0.0.0.0:4443
#   SSH3_URL_PATH       /ssh3
#   SSH3_USER           tunneluser
#   SSH3_USER_UID       1000
#
# Mounts expected (from docker-compose.yml):
#   /run/secrets/cert.pem            TLS cert
#   /run/secrets/cert.key            TLS key
#   /run/secrets/authorized_id.pub   client public key
set -euo pipefail

BIND="${SSH3_BIND:-0.0.0.0:4443}"
URL_PATH="${SSH3_URL_PATH:-/ssh3}"
USER_NAME="${SSH3_USER:-tunneluser}"
USER_UID="${SSH3_USER_UID:-1000}"

CERT=/run/secrets/cert.pem
KEY=/run/secrets/cert.key
AUTH_KEY=/run/secrets/authorized_id.pub

for f in "$CERT" "$KEY" "$AUTH_KEY"; do
    if [[ ! -r "$f" ]]; then
        echo "missing required secret file: $f" >&2
        exit 1
    fi
done

# Idempotent user creation.  Inside the container, /etc/passwd is the
# container's own copy - we never touch the host.
if ! id -u "$USER_NAME" >/dev/null 2>&1; then
    adduser -D -u "$USER_UID" -s /bin/sh "$USER_NAME"
fi
HOME_DIR="$(getent passwd "$USER_NAME" | cut -d: -f6)"

# Install authorized_identities for this user.  ssh3-server reads from
# ~/.ssh3/authorized_identities (and ~/.ssh/authorized_keys as a
# fallback) - we use the former because it's the documented path.
install -d -m 0700 -o "$USER_NAME" -g "$USER_NAME" "$HOME_DIR/.ssh3"
install -m 0600 -o "$USER_NAME" -g "$USER_NAME" "$AUTH_KEY" "$HOME_DIR/.ssh3/authorized_identities"

# ssh3-server's log file is hard-coded to /var/log/ssh3.log when -v is
# not set; we use -v so it logs to stderr.  That's what docker logs.
exec ssh3-server \
    -bind "$BIND" \
    -url-path "$URL_PATH" \
    -cert "$CERT" \
    -key "$KEY" \
    -v
