#!/bin/bash
# OFFLINE ONLY. Fresh root-owned receipt and audited launcher REQUIRED.
set -euo pipefail
umask 077
[[ $(id -u) == 0 ]] || exit 1
D=/var/lib/ssh3-rs-handoff-gambetta-v5
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
 [[ $(docker inspect --format '{{.Id}}' autossh-ssh3) == "$(get "$D/identity" container_id)" ]] || exit 1
 [[ $(get "$D/identity" container_id) =~ ^[0-9a-f]{64}$ ]] || exit 1
 init=$(get "$D/identity" init_pid)
 [[ $init =~ ^[1-9][0-9]*$ ]] || exit 1
 [[ $(docker inspect --format '{{.State.Pid}}' autossh-ssh3) == "$init" ]] || exit 1
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
signal_role() { check_pid "$1" "$2"; printf 'handoff gambetta role=%s PID=%s signal=%s\n' "$1" "$pid" "$3"; kill -s "$3" "$pid"; }

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
command -v flock >/dev/null
[[ -x $D/fsync-path ]] || exit 1
docker exec autossh-ssh3 sh -c "command -v bash; command -v flock; command -v ss; test -x /opt/ssh3-rs-handoff-v5/fsync-path" >/dev/null
validate_artifacts
[[ $(get "$D/identity" route_reviewed) == yes ]] || exit 1
[[ $(get "$D/identity" container_gate_preflight) == yes ]] || exit 1
[[ $(get "$D/identity" irreversible_stream_reset_authorized) == yes ]] || exit 1
# Owner/root/hash/mount and tool availability must be verified by the coordinator
# before this receipt. No private key content is copied by these scripts.
actual=$(docker exec autossh-ssh3 sha256sum /opt/ssh3-rs-handoff-v5/gate.sh)
expected=$(sha256sum "$D/container-gate.sh")
[[ ${actual%% *} == "${expected%% *}" ]] || exit 1
check_pid autossh "$D/identity"
watchdog=$(get "$D/identity" watchdog_present)
[[ $watchdog == yes || $watchdog == no ]] || exit 1
if [[ $watchdog == yes ]]; then check_pid watchdog "$D/identity"; fi
check_pid go "$D/identity"
# Require a fresh state dir and timer name. No silent retry of partial rollout.
[[ ! -e $D/phase && ! -e $D/rollback-begun ]] || exit 1
systemd-run --unit=ssh3-gambetta-handoff-rollback-v5 --on-active=120s "$D/rollback.sh"
systemctl is-active --quiet ssh3-gambetta-handoff-rollback-v5.timer
lock; not_rolled_back
phase BEFORE_AUTOSSH_STOP
signal_role autossh "$D/identity" STOP
phase BEFORE_WATCHDOG_STOP
if [[ $watchdog == yes ]]; then signal_role watchdog "$D/identity" STOP; fi
phase BEFORE_GO_TERM
signal_role go "$D/identity" TERM
phase WAIT_GO_EXIT
oldpid=$pid
oldstart=$start
exited=no
for attempt in {1..30}; do
 if [[ ! -e /proc/$oldpid/stat ]]; then exited=yes; break; fi
 st=$(cat "/proc/$oldpid/stat"); st=${st##*) }; read -ra f <<< "$st"
 [[ ${f[19]} == "$oldstart" ]] || { unlock; "$D/rollback.sh"; exit 1; }
 if [[ ${f[0]} == Z ]]; then exited=yes; break; fi
 sleep 0.1
done
if [[ $exited != yes ]]; then unlock; "$D/rollback.sh"; exit 1; fi
phase WAIT_REMOTE_RELEASE
# Request created under host lock after verified Go exit. Durable atomic rename.
python3 "$D/request-writer.py" "$D/release-request.json" "$oldpid" "$oldstart"
unlock
if ! python3 "$D/receipt-barrier.py" --request "$D/release-request.json" --receipt "$D/remote-release-receipt.json" --ports t64070 t49167 t49160 u64443 --timeout 30; then
 "$D/rollback.sh"; exit 1
fi
lock
not_rolled_back
if ! python3 "$D/receipt-barrier.py" --request "$D/release-request.json" --receipt "$D/remote-release-receipt.json" --ports t64070 t49167 t49160 u64443 --recheck; then
 unlock; "$D/rollback.sh"; exit 1
fi
phase BEFORE_LAUNCH
unlock
if ! localbind=$(docker exec autossh-ssh3 ss -H -tln 'sport = :3180'); then "$D/rollback.sh"; exit 1; fi
[[ -z $localbind ]] || { "$D/rollback.sh"; exit 1; }
# Container gate will reject launch if rollback wins the race. A controller
# dying during docker exec leaves identity inside the container for cancel.
check_context
docker exec -d autossh-ssh3 bash /opt/ssh3-rs-handoff-v5/gate.sh launch
lock; not_rolled_back; phase LAUNCH_REQUESTED; unlock
printf 'UNACCEPTED: timer armed; exact caller and forward checks required\n'
