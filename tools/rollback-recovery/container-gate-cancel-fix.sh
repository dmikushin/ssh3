#!/bin/bash
# Staged unchanged INSIDE existing container at /opt/ssh3-rs-handoff-mux-20261026/gate.sh.
set -euo pipefail
umask 077
S=/opt/ssh3-rs-handoff-mux-20261026
[[ -d $S && ! -L $S && $(stat -c %u "$S") == 0 ]] || exit 1
(( (8#$(stat -c %a "$S") & 8#022) == 0 )) || exit 1
exec 8>"$S/gate.lock"
flock -x 8
start_of() { local s; s=$(cat "/proc/$1/stat"); s=${s##*) }; read -ra fields <<< "$s"; printf '%s' "${fields[19]}"; }
case ${1:-} in
 cancel)
  # Persist cancellation BEFORE inspecting launcher identity. This lock is also
  # acquired by every future launch, including an already-queued DockerExec.
  printf 'cancelled\n' > "$S/cancelled"; "$S/fsync-path" "$S/cancelled"; "$S/fsync-path" "$S"
  if [[ -f $S/rust.pid ]]; then
   read -r p birth < "$S/rust.pid"
   [[ $p =~ ^[1-9][0-9]*$ && $p != 1 ]] || exit 1
   snapshot() {
    local raw
    if raw=$(cat "/proc/$p/stat"); then
     raw=${raw##*) }; read -ra state_fields <<< "$raw"
     [[ ${state_fields[19]} == "$birth" ]] || { printf 'recorded Rust PID reused; refusing signal\n' >&2; return 2; }
     [[ ${state_fields[0]} != Z ]] || return 3
     return 0
    fi
    # ENOENT after a prior existence check is normal process exit. Any read
    # failure while the PID still exists remains fatal, never silently ignored.
    [[ ! -e /proc/$p/stat ]] && return 3
    printf 'container gate: cannot read owned process identity\n' >&2; return 2
   }
   rc=0; snapshot || rc=$?
   case $rc in
    3) ;; # Already gone/zombie: cancellation is idempotent.
    0)
     printf 'container gate: terminating owned launcher/Rust PID=%s start=%s\n' "$p" "$birth"
     if ! kill -TERM "$p"; then
      rc=0; snapshot || rc=$?
      [[ $rc == 3 ]] || exit 1
     fi
     exited=no
     for attempt in {1..30}; do
      rc=0; snapshot || rc=$?
      case $rc in 3) exited=yes; break;; 0) sleep 0.1;; *) exit 1;; esac
     done
     [[ $exited == yes ]] || exit 1;;
    *) exit 1;;
   esac
  fi
  printf 'CANCELLED_OWNED_PROCESS_EXITED\n'; exit 0;;
 launch)
  [[ ! -e $S/cancelled && ! -e $S/rust.pid ]] || exit 1
  (cd "$S" && sha256sum --check --strict artifacts.sha256)
  actual=$(sha256sum "$S/ssh3-rs"); [[ ${actual%% *} == 22d7ae4e72da841cad92ca021d7230e3a97dbb9c0944169e22590e1d6b6f425d ]] || exit 1
  # PID identity is persisted before releasing gate lock and before exec. Exec
  # preserves PID/starttime: cancel may terminate either launcher or Rust.
  printf '%s %s\n' "$$" "$(start_of $$)" > "$S/rust.pid"
  "$S/fsync-path" "$S/rust.pid"; "$S/fsync-path" "$S"
  flock -u 8; exec 8>&-
  exec "$S/ssh3-rs" -F "$S/bridge.conf" -N -o ExitOnForwardFailure=yes -R 127.0.0.1:64070:172.17.0.1:22 -L 0.0.0.0:3180:127.0.0.1:3180 -R 127.0.0.1:49167:172.17.0.1:11435 -R 127.0.0.1:49160:172.17.0.1:49160 -u 64443:172.17.0.1:443 oracle-rs-cutover
  ;;
 *) exit 64;;
esac
