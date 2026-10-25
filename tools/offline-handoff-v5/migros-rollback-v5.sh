#!/bin/bash
# OFFLINE ONLY. Fresh root-owned receipt and audited launcher REQUIRED.
set -euo pipefail
umask 077
[[ $(id -u) == 0 ]] || exit 1
D=/var/lib/ssh3-rs-handoff-migros-v5
[[ -d $D && ! -L $D && $(stat -c %u "$D") == 0 ]] || exit 1
(( (8#$(stat -c %a "$D") & 8#022) == 0 )) || exit 1
get() {
 local file=$1 key=$2 value
 [[ -f $file && ! -L $file && $(stat -c %u "$file") == 0 ]] || exit 1
 (( (8#$(stat -c %a "$file") & 8#022) == 0 )) || exit 1
 [[ $(grep -c "^$key=" "$file") == 1 ]] || exit 1
 value=$(grep "^$key=" "$file"); printf '%s' "${value#*=}"
}
check_context() {
 [[ $(cat /proc/sys/kernel/random/boot_id) == "$(get "$D/identity" boot_id)" ]] || exit 1
 [[ $(docker inspect --format '{{.Id}}' autossh-ssh3-migros) == "$(get "$D/identity" container_id)" ]] || exit 1
 [[ $(get "$D/identity" container_id) =~ ^[0-9a-f]{64}$ ]] || exit 1
 init=$(get "$D/identity" init_pid)
 [[ $init =~ ^[1-9][0-9]*$ ]] || exit 1
 [[ $(docker inspect --format '{{.State.Pid}}' autossh-ssh3-migros) == "$init" ]] || exit 1
 [[ $(readlink "/proc/$init/ns/net") == "$(get "$D/identity" netns)" ]] || exit 1
}
check_pid() {
 local role=$1 file=$2
 check_context
 pid=$(get "$file" "${role}_pid"); start=$(get "$file" "${role}_start")
 [[ $pid =~ ^[1-9][0-9]*$ && $pid != "$init" ]] || exit 1
 statline=$(cat "/proc/$pid/stat"); statline=${statline##*) }
 read -ra fields <<< "$statline"
 [[ ${fields[19]} == "$start" ]] || exit 1
 [[ $(readlink "/proc/$pid/ns/net") == "$(get "$D/identity" netns)" ]] || exit 1
 hash=$(sha256sum "/proc/$pid/exe"); [[ ${hash%% *} == "$(get "$file" "${role}_exe_sha256")" ]] || exit 1
 [[ ${fields[1]} == "$(get "$file" "${role}_ppid")" ]] || exit 1
}
signal_role() { check_pid "$1" "$2"; printf 'handoff migros role=%s PID=%s signal=%s\n' "$1" "$pid" "$3"; kill -s "$3" "$pid"; }

# Same host transaction lock serializes signals/journal with rollback. Container
# launch/cancel has its own lock so queued DockerExec cannot launch after cancel.
lock() { exec 9>"$D/host.lock"; flock -x 9; }
unlock() { flock -u 9; exec 9>&-; }
phase() { printf '%s\n' "$1" > "$D/phase.next"; $D/fsync-path "$D/phase.next"; mv "$D/phase.next" "$D/phase"; $D/fsync-path "$D"; }
not_rolled_back() { [[ ! -e $D/rollback-begun && ! -e $D/accepted ]] || exit 1; }
validate_artifacts() {
 for f in "$D/rollback.sh" "$D/container-gate.sh" "$D/bridge.conf" "$D/known_hosts" "$D/launch-artifacts.sha256"; do
  [[ -f $f && ! -L $f && $(stat -c %u "$f") == 0 ]] || exit 1
  (( (8#$(stat -c %a "$f") & 8#022) == 0 )) || exit 1
 done
 (cd "$D" && sha256sum --check --strict launch-artifacts.sha256)
}

check_context
validate_artifacts
lock
if [[ -f $D/accepted ]]; then unlock; exit 0; fi
printf 'rollback\n' > "$D/rollback-begun"; $D/fsync-path "$D/rollback-begun"; $D/fsync-path "$D"
phase ROLLBACK_CANCELLING
unlock
# Must cancel successfully even if launch is delayed/partially delivered. Do not
# CONT old supervisors while replacement state remains unknown.
check_context
docker exec autossh-ssh3-migros bash /opt/ssh3-rs-handoff-v5/gate.sh cancel
lock
phase BEFORE_AUTOSSH_CONT
signal_role autossh "$D/identity" CONT
if [[ $(get "$D/identity" watchdog_present) == yes ]]; then
 phase BEFORE_WATCHDOG_CONT
 signal_role watchdog "$D/identity" CONT
fi
phase ROLLBACK_RESUMED_UNVERIFIED
unlock
printf 'Rollback supervisors resumed; actual provider/forward health NOT asserted\n'
