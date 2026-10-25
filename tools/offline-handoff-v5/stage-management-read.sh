#!/bin/bash
# PREPARATION ONLY. Coordinator must review/freeze/copy as root before running.
set -euo pipefail
umask 077
[[ $(id -u) == 0 ]] || exit 1
[[ $# == 1 ]] || { printf 'usage: stage-management-read.sh ROOT_OWNED_REVIEWED_INPUT_DIRECTORY\n' >&2; exit 64; }
INPUT=$1
ROOT=/var/lib/ssh3-rs-management-read-20261025
[[ $INPUT == /* && -d $INPUT && ! -L $INPUT && $(stat -c %u "$INPUT") == 0 ]] || exit 1
(( (8#$(stat -c %a "$INPUT") & 8#022) == 0 )) || exit 1
[[ ! -e $ROOT && ! -L $ROOT ]] || { printf 'staging exists; inspect, do not overwrite\n' >&2; exit 1; }
# Input manifest/ancestor verification is performed by the independent root
# dispatcher before this script, never inferred from caller-provided checksum.
for required in oracle-read-adapter.py offline-transport-v5.py observe-release-frozen-4bbe.py receipt-barrier-v5.py management-agent-policy.py collect-oracle-ports.sh management-read.conf invoke-management-read.py copyback-management-receipt.py tcp2221-known_hosts agent-approval.json oracle-boot.json; do
 [[ -f $INPUT/$required && ! -L $INPUT/$required ]] || exit 1
 matches=0
 while read -r digest filename; do
  if [[ $filename == "$required" ]]; then (( matches += 1 )); fi
 done < "$INPUT/STAGING.sha256"
 [[ $matches == 1 ]] || exit 1
done
(cd "$INPUT" && sha256sum --check --strict STAGING.sha256)
install -d -o root -g root -m700 "$ROOT" "$ROOT/source"
for name in oracle-read-adapter.py offline-transport-v5.py observe-release-frozen-4bbe.py receipt-barrier-v5.py management-agent-policy.py collect-oracle-ports.sh; do
 install -o root -g root -m400 "$INPUT/$name" "$ROOT/source/$name"
done
install -o root -g root -m400 "$INPUT/management-read.conf" "$ROOT/management.conf"
install -o root -g root -m400 "$INPUT/invoke-management-read.py" "$ROOT/invoke.py"
install -o root -g root -m400 "$INPUT/copyback-management-receipt.py" "$ROOT/copyback.py"
# These are PUBLIC TCP2221 pin lines and explicit current approval observations,
# not private keys, fabricated defaults or Rust UDP pin substitutes.
for name in tcp2221-known_hosts agent-approval.json oracle-boot.json; do
 install -o root -g root -m400 "$INPUT/$name" "$ROOT/$name"
done
printf 'MANAGEMENT_SOURCE_STAGED_UNEXECUTED\n'
