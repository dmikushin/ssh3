#!/bin/sh
# Runs as root of a private user+mount+pid namespace created by
# scripts/root-mode-test.sh (root inside = the invoking user outside; uids
# 1..65536 inside = the invoking user's subuid range). Two throwaway accounts
# exist only through bind-mounted /etc/passwd and /etc/group in this mount
# namespace; their homes and keys live under $W. A private devpts instance
# gives real ptys. ssh3-server runs as this root; every check goes through the
# real ssh3 client. Prints "PASS <check>" / "FAIL <check>: ..." per check and
# exits non-zero on any failure.
set -eu
B=${1:?bin dir}
W=${2:?work dir}
fails=0
pass() { echo "PASS $1"; }
fail() { echo "FAIL $1: $2"; fails=$((fails+1)); }

# Accounts: same uids/gids as a real system would hand out; alice is also in
# the supplementary group proj, which initgroups must apply.
{
    echo "root:x:0:0:root:/root:/bin/sh"
    echo "alice:x:1001:1001:alice:$W/home/alice:/bin/sh"
    echo "bob:x:1002:1002:bob:$W/home/bob:/bin/sh"
} > "$W/passwd"
{
    echo "root:x:0:"
    echo "tty:x:5:"
    echo "alice:x:1001:"
    echo "bob:x:1002:"
    echo "proj:x:2000:alice"
} > "$W/group"
mount --bind "$W/passwd" /etc/passwd
mount --bind "$W/group" /etc/group
mount -t devpts -o newinstance,ptmxmode=0666,mode=0620,gid=5 devpts /dev/pts
mount --bind /dev/pts/ptmx /dev/ptmx

for u in alice:1001 bob:1002; do
    name=${u%%:*}; id=${u##*:}
    ssh-keygen -q -t ed25519 -N '' -C "$name" -f "$W/$name.key"
    install -d -m 700 -o "$id" -g "$id" "$W/home/$name" "$W/home/$name/.ssh"
    install -m 600 -o "$id" -g "$id" "$W/$name.key.pub" "$W/home/$name/.ssh/authorized_keys"
done
ssh-keygen -q -t ed25519 -N '' -f "$W/host_key"

cat > "$W/server.toml" <<EOF
listen = "127.0.0.1:0"
host_key = "$W/host_key"
endpoint_keys = "$W/endpoint-keys"
authorized_keys = "%h/.ssh/authorized_keys"
EOF
"$B/ssh3-server" -f "$W/server.toml" > "$W/server.log" 2>&1 &
SP=$!
i=0
while ! grep -q 'listening on' "$W/server.log"; do
    i=$((i+1)); [ $i -gt 200 ] && { echo "FAIL server-start: $(cat "$W/server.log")"; exit 1; }
    sleep 0.05
done
PORT=$(grep -o 'listening on [^ ]*' "$W/server.log" | sed 's/.*://')
printf '[127.0.0.1]:%s %s\n' "$PORT" "$(cut -d' ' -f1,2 "$W/host_key.pub")" > "$W/known_hosts"
for u in alice bob; do
    for k in alice bob; do
        cat > "$W/cfg-$u-$k" <<EOF
Host t
  HostName 127.0.0.1
  Port $PORT
  User $u
  IdentityFile $W/$k.key
  IdentitiesOnly yes
  UserKnownHostsFile $W/known_hosts
  StrictHostKeyChecking yes
  BatchMode yes
EOF
    done
done
c() { u=$1; k=$2; shift 2; "$B/ssh3" -F "$W/cfg-$u-$k" "$@"; }

# 1. identity: uid, primary gid, supplementary groups, as initgroups gives.
got=$(c alice alice t 'id -u; id -g; id -G | tr " " "\n" | sort -n | tr "\n" " "')
exp=$(printf '1001\n1001\n1001 2000 ')
[ "$got" = "$exp" ] && pass "alice uid/gid/groups (1001/1001/1001,2000)" || fail "alice uid/gid/groups" "got [$got]"
got=$(c bob bob t 'id -u; id -g; id -G')
exp=$(printf '1002\n1002\n1002')
[ "$got" = "$exp" ] && pass "bob uid/gid/groups (1002/1002/1002)" || fail "bob uid/gid/groups" "got [$got]"

# 2. login environment and working directory.
got=$(c alice alice t 'echo "$USER $LOGNAME $HOME $SHELL"; pwd')
exp=$(printf 'alice alice %s /bin/sh\n%s' "$W/home/alice" "$W/home/alice")
[ "$got" = "$exp" ] && pass "alice USER/LOGNAME/HOME/SHELL + cwd" || fail "alice env+cwd" "got [$got]"

# 3. no privilege left: all four uid/gid slots dropped, no effective caps.
got=$(c bob bob t 'grep -E "^(Uid|Gid|CapEff):" /proc/self/status | tr -s "\t" " "')
exp=$(printf 'Uid: 1002 1002 1002 1002\nGid: 1002 1002 1002 1002\nCapEff: 0000000000000000')
[ "$got" = "$exp" ] && pass "bob: Uid/Gid all 1002, CapEff 0" || fail "bob no privileges left" "got [$got]"

# 4. pty owned by the session user, mode 0620 (group tty), as sshd does.
got=$(c alice alice -tt t 'stat -c "%u %g %a" $(tty)' < /dev/null | tr -d '\r')
case "$got" in
    "1001 5 620"|"1001 1001 620"|"1001 5 600"|"1001 1001 600") pass "alice pty owner/group/mode ($got)" ;;
    *) fail "alice pty owner/mode" "got [$got]" ;;
esac

# 5. per-user authorized_keys: a key opens only its own account.
if c bob alice t true 2> "$W/cross.err"; then
    fail "alice key refused for bob" "login succeeded"
else
    grep -q 'Permission denied' "$W/cross.err" && pass "alice's key refused for bob (Permission denied)" \
        || fail "alice key refused for bob" "$(cat "$W/cross.err")"
fi

# 6. the session cannot write root-owned files.
got=$(c alice alice t 'touch /etc/ssh3-probe 2>/dev/null; echo rc=$?')
case "$got" in *"rc=0"*) fail "alice cannot write /etc" "touch succeeded" ;; *) pass "alice cannot write /etc ($got)" ;; esac

kill "$SP"
wait "$SP" 2>/dev/null || true
[ "$fails" -eq 0 ] && echo "ALL PASS" || { echo "$fails FAILED"; exit 1; }
