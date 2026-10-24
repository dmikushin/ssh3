#!/bin/sh
# Root-mode check for ssh3-server: as root it must serve several accounts,
# each with its own uid/gid/groups, HOME, pty ownership and authorized_keys.
#
# Unprivileged: runs inside a private user+mount+pid namespace (unshare). Root
# there is your own uid outside; the test accounts exist only through
# bind-mounted /etc/passwd and /etc/group in that namespace, with uids mapped
# into your subuid range; ptys come from a private devpts instance. No system
# account, file, container storage or network is touched; the server listens
# on 127.0.0.1 only.
#
# Usage: scripts/root-mode-test.sh [bin-dir]
#   bin-dir: holds ssh3 and ssh3-server, default dist/ (build-release.sh).
# Needs: util-linux unshare with --map-auto, newuidmap/newgidmap, subuid and
# subgid ranges for your user, ssh-keygen.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
bin=$(cd "${1:-$here/../dist}" && pwd)
for b in ssh3 ssh3-server; do
    [ -x "$bin/$b" ] || { echo "root-mode-test: $bin/$b missing (run scripts/build-release.sh)" >&2; exit 2; }
done
# Work dir must be traversable by the test uids (home dirs usually are not)
# and small: /dev/shm, removed afterwards.
W=$(mktemp -d /dev/shm/ssh3-root-mode.XXXXXX)
chmod 755 "$W"
trap 'unshare --map-root-user --map-auto rm -rf "$W"' EXIT
unshare --map-root-user --map-auto --mount --pid --fork --kill-child \
    sh "$here/root-mode/inside.sh" "$bin" "$W"
