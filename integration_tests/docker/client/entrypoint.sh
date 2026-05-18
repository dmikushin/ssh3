#!/usr/bin/env bash
# Client entrypoint.  Long-running reconnect loop: if ssh3 ever
# returns we sleep SSH3_RECONNECT_DELAY and rerun.  The QUIC
# connection-migration coordinator (-enable-migration) handles in-
# session network changes; this wrapper handles total connection
# loss (server restart, NAT cleared the binding, long blackhole
# exceeded the QUIC idle timeout, etc.) - the autossh equivalent
# for OpenSSH.
#
# Env vars:
#   SSH3_REMOTE_USER         user on the remote ssh3-server
#   SSH3_REMOTE_HOST         host:port of the remote (e.g. server:4443)
#   SSH3_REMOTE_PATH         URL path of the ssh3 endpoint (default /ssh3)
#   SSH3_OPTIONS             extra args to ssh3 (forwards, reverse-forwards, etc.)
#   SSH3_RECONNECT_DELAY     seconds between reconnect attempts (default 5)
#   SSH3_ENABLE_MIGRATION    set non-empty to add -enable-migration
#   SSH3_INSECURE            set non-empty to add -insecure (self-signed cert)
#   SSH3_REMOTE_COMMAND      remote command to run; default 'sleep infinity'
#                             (mirroring jnovack/autossh which holds the
#                             tunnel open without an interactive shell)
#
# Mounts expected:
#   /run/secrets/id_ed25519  client private key matched by the server's
#                             authorized_identities
set -euo pipefail

: "${SSH3_REMOTE_USER:?must set SSH3_REMOTE_USER}"
: "${SSH3_REMOTE_HOST:?must set SSH3_REMOTE_HOST (e.g. server:4443)}"
REMOTE_PATH="${SSH3_REMOTE_PATH:-/ssh3}"
RECONNECT_DELAY="${SSH3_RECONNECT_DELAY:-5}"
REMOTE_CMD="${SSH3_REMOTE_COMMAND:-sleep infinity}"

KEY=/run/secrets/id_ed25519
if [[ ! -r "$KEY" ]]; then
    echo "missing required private-key mount at $KEY" >&2
    exit 1
fi
# ssh3 refuses keys with world-readable permissions.
cp "$KEY" /tmp/id_ed25519
chmod 0600 /tmp/id_ed25519

ARGS=( -privkey /tmp/id_ed25519 )
if [[ -n "${SSH3_INSECURE:-}" ]]; then
    ARGS+=( -insecure )
fi
if [[ -n "${SSH3_ENABLE_MIGRATION:-}" ]]; then
    ARGS+=( -enable-migration )
fi
# Forwards / reverse-forwards / extra flags.  Word-split intentionally
# so multiple -reverse-tcp specs in SSH3_OPTIONS get passed as
# distinct args - this mirrors how jnovack/autossh shells out
# SSH_OPTIONS.
if [[ -n "${SSH3_OPTIONS:-}" ]]; then
    # shellcheck disable=SC2206
    EXTRA=( ${SSH3_OPTIONS} )
    ARGS+=( "${EXTRA[@]}" )
fi
URL="${SSH3_REMOTE_USER}@${SSH3_REMOTE_HOST}${REMOTE_PATH}"

# Term handler so docker stop / compose down doesn't have to wait
# the full reconnect delay or kill ssh3 mid-handshake.
CHILD_PID=
shutdown() {
    if [[ -n "$CHILD_PID" ]]; then
        kill -TERM "$CHILD_PID" 2>/dev/null || true
    fi
    exit 0
}
trap shutdown TERM INT

while true; do
    echo "ssh3 client: connecting to $URL"
    # shellcheck disable=SC2086
    ssh3 "${ARGS[@]}" "$URL" $REMOTE_CMD &
    CHILD_PID=$!
    wait "$CHILD_PID" || true
    CHILD_PID=
    echo "ssh3 client: session ended, reconnecting in ${RECONNECT_DELAY}s"
    sleep "$RECONNECT_DELAY"
done
