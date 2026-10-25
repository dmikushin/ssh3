#!/bin/bash
# Staged unchanged INSIDE existing container at /opt/ssh3-rs-handoff-v5/gate.sh.
set -euo pipefail
umask 077
S=/opt/ssh3-rs-handoff-v5
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
   if [[ -e /proc/$p/stat ]]; then
    if [[ $(start_of "$p") != "$birth" ]]; then
     printf 'recorded Rust PID reused; refusing signal\n' >&2; exit 1
    fi
    printf 'container gate: terminating owned launcher/Rust PID=%s start=%s\n' "$p" "$birth"
    kill -TERM "$p"
    exited=no
    for attempt in {1..30}; do
     if [[ ! -e /proc/$p/stat ]]; then exited=yes; break; fi
     state=$(cat "/proc/$p/stat"); state=${state##*) }
     if [[ ${state%% *} == Z ]]; then exited=yes; break; fi
     [[ $(start_of "$p") == "$birth" ]] || exit 1
     sleep 0.1
    done
    [[ $exited == yes ]] || exit 1
   fi
  fi
  printf 'CANCELLED_OWNED_PROCESS_EXITED\n'; exit 0;;
 launch)
  [[ ! -e $S/cancelled && ! -e $S/rust.pid ]] || exit 1
  (cd "$S" && sha256sum --check --strict artifacts.sha256)
  actual=$(sha256sum "$S/ssh3-rs"); [[ ${actual%% *} == d455dfda32d402972fc28951d1a17835eecb92f31c74f40fba9822dfaab7146d ]] || exit 1
  # PID identity is persisted before releasing gate lock and before exec. Exec
  # preserves PID/starttime: cancel may terminate either launcher or Rust.
  printf '%s %s\n' "$$" "$(start_of $$)" > "$S/rust.pid"
  "$S/fsync-path" "$S/rust.pid"; "$S/fsync-path" "$S"
  flock -u 8; exec 8>&-
  exec "$S/ssh3-rs" -F "$S/bridge.conf" -N -o ExitOnForwardFailure=yes -R 127.0.0.1:49171:172.17.0.1:22 -L 0.0.0.0:3180:127.0.0.1:3180 -u 64447:172.17.0.1:60443 oracle-rs-cutover
  ;;
 *) exit 64;;
esac
