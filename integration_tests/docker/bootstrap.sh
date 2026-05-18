#!/usr/bin/env bash
# Generate the per-deployment secrets the compose stack needs:
#   - a self-signed TLS cert for the ssh3 server,
#   - an ed25519 key pair for the ssh3 client.
#
# Idempotent: existing files are kept untouched.  Re-run only if you
# want to rotate.
#
# Output: ./secrets/{cert.pem,cert.key,client_id_ed25519,client_id_ed25519.pub}
#
# This script runs on the HOST.  It does NOT need root (no useradd, no
# iptables, no sysctl - none of the things the in-tree
# `local-integration-tests` target does to your machine).  Everything
# stays in ./secrets/.
set -euo pipefail

cd "$(dirname "$0")"
mkdir -p secrets
chmod 0700 secrets

CERT=secrets/cert.pem
KEY=secrets/cert.key
PRIV=secrets/client_id_ed25519
PUB="${PRIV}.pub"

if [[ ! -f "$CERT" || ! -f "$KEY" ]]; then
    echo "generating self-signed TLS cert"
    openssl req -x509 -sha256 -nodes -newkey rsa:4096 \
        -keyout "$KEY" -out "$CERT" -days 365 \
        -subj "/C=XX/O=ssh3-docker-smoke/CN=server" \
        -addext "subjectAltName = DNS:server,IP:10.20.0.10" \
        >/dev/null 2>&1
    chmod 0400 "$KEY"
    chmod 0444 "$CERT"
else
    echo "TLS cert already present at $CERT, skipping"
fi

if [[ ! -f "$PRIV" || ! -f "$PUB" ]]; then
    echo "generating ed25519 client key"
    ssh-keygen -t ed25519 -N "" -C ssh3-docker-smoke-client -f "$PRIV" >/dev/null
    chmod 0400 "$PRIV"
    chmod 0444 "$PUB"
else
    echo "client key already present at $PRIV, skipping"
fi

echo
echo "secrets/ contents:"
ls -la secrets/
echo
echo "Run:    docker compose up --build"
echo "Stop:   docker compose down"
echo "Reset:  docker compose down --rmi local -v && rm -rf secrets && ./bootstrap.sh"
