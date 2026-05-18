#!/usr/bin/env bash
# Smoke tests for the in-tree docker stack.  Runs INSIDE the tester
# container, attached to the same internal ssh3net bridge as server.
# Nothing on the host is touched.
#
# Tests:
#   1. echo   - run `echo HELLO` via ssh3 on the server, expect it
#               back on stdout.
#   2. reverse-tcp - start an HTTP origin inside the tester on
#               127.0.0.1:18765; ask the server to expose port 28765
#               via -reverse-tcp; curl http://server:28765 from
#               inside the tester (which lives on the same docker
#               network as the server) and assert we get the origin's
#               body.
#
# Exit code = number of failed tests; 0 means all pass.

set -u

KEY=/run/secrets/id_ed25519
SERVER_USER="${SSH3_REMOTE_USER:-tunneluser}"
SERVER_HOST="${SSH3_REMOTE_HOST:-server:4443}"
SERVER_PATH="${SSH3_REMOTE_PATH:-/ssh3}"
URL="${SERVER_USER}@${SERVER_HOST}${SERVER_PATH}"

cp "$KEY" /tmp/id_ed25519
chmod 0600 /tmp/id_ed25519

SSH3=(ssh3 -privkey /tmp/id_ed25519 -insecure)

failed=0
fail() {
    echo "FAIL: $*" >&2
    failed=$((failed + 1))
}
pass() {
    echo "PASS: $*"
}

# ----------------------------------------------------------------------
# Test 1: echo
# ----------------------------------------------------------------------
echo "=== test 1: ssh3 echo ==="
out="$( "${SSH3[@]}" "$URL" /bin/echo HELLO_FROM_SERVER 2>/tmp/ssh3-echo.err </dev/null )"
rc=$?
# The remote stdout comes over a PTY-wrapped channel, so we get a
# trailing \r\n.  Match the payload as a substring, not a strict
# string-equality, so the trailing whitespace doesn't fail the test.
if [[ $rc -ne 0 ]]; then
    sed -n '1,20p' /tmp/ssh3-echo.err
    fail "ssh3 echo exited $rc"
elif [[ "$out" != *HELLO_FROM_SERVER* ]]; then
    printf 'out=%q\n' "$out" >&2
    fail "ssh3 echo did not contain HELLO_FROM_SERVER"
else
    pass "ssh3 echo returns the expected string"
fi

# ----------------------------------------------------------------------
# Test 2: reverse-tcp
# ----------------------------------------------------------------------
echo
echo "=== test 2: reverse-tcp ==="
ORIGIN_PORT=18765
REVERSE_PORT=28765

# Inline shell responder.  socat's SYSTEM:/EXEC: don't go through a
# real shell unless we hand them one explicitly; an inline /tmp script
# keeps the HTTP response well-formed (CRLF, Content-Length, the lot).
cat >/tmp/respond.sh <<'RESPOND'
#!/bin/sh
printf 'HTTP/1.1 200 OK\r\nContent-Length: 13\r\nConnection: close\r\n\r\nREV_TUNNEL_OK'
RESPOND
chmod +x /tmp/respond.sh

socat TCP-LISTEN:${ORIGIN_PORT},bind=127.0.0.1,reuseaddr,fork \
      EXEC:/tmp/respond.sh &
ORIGIN_PID=$!
cleanup() {
    kill "$ORIGIN_PID" 2>/dev/null || true
    [[ -n "${SSH3_PID:-}" ]] && kill "$SSH3_PID" 2>/dev/null || true
}
trap cleanup EXIT

for _ in 1 2 3 4 5 6 7 8 9 10; do
    if (exec 9<>/dev/tcp/127.0.0.1/${ORIGIN_PORT}) 2>/dev/null; then
        exec 9>&- 9<&-
        break
    fi
    sleep 0.1
done

"${SSH3[@]}" \
    -reverse-tcp "${ORIGIN_PORT}/127.0.0.1@${REVERSE_PORT}/0.0.0.0" \
    "$URL" sleep 60 \
    >/tmp/ssh3-rev.out 2>/tmp/ssh3-rev.err </dev/null &
SSH3_PID=$!

ok=0
for _ in $(seq 1 30); do
    body="$(curl -s --max-time 2 http://server:${REVERSE_PORT}/ 2>/dev/null)"
    if [[ "$body" == "REV_TUNNEL_OK" ]]; then
        ok=1
        break
    fi
    sleep 0.5
done

kill "$SSH3_PID" 2>/dev/null || true
wait "$SSH3_PID" 2>/dev/null || true
SSH3_PID=

if [[ $ok -ne 1 ]]; then
    echo "--- ssh3 stderr ---"
    sed -n '1,40p' /tmp/ssh3-rev.err
    fail "reverse-tcp did not deliver origin tag through the tunnel"
else
    pass "reverse-tcp: curl http://server:${REVERSE_PORT} returned origin tag"
fi

kill "$ORIGIN_PID" 2>/dev/null || true
wait "$ORIGIN_PID" 2>/dev/null || true

echo
if [[ $failed -eq 0 ]]; then
    echo "=== ALL TESTS PASSED ==="
else
    echo "=== $failed TEST(S) FAILED ==="
fi
exit $failed
