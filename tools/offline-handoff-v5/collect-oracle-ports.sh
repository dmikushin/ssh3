#!/bin/bash
# Read-only Oracle snapshot. No client-PID lookup: client exit is host evidence.
set -euo pipefail
export LC_ALL=C
[[ $# -gt 0 && $# -le 16 ]] || exit 64
for token in "$@"; do
 [[ $token =~ ^[tu][1-9][0-9]{0,4}$ ]] || exit 64
 (( ${token:1} <= 65535 )) || exit 64
done
printf 'SSH3_PORT_SNAPSHOT_V1\n'
printf 'HOST '; hostname
printf 'BOOT '; read -r boot < /proc/sys/kernel/random/boot_id; printf '%s\n' "$boot"
for token in "$@"; do
 case $token in t*) flag=-tln;; u*) flag=-uln;; esac
 # Capture at most 16385 bytes. pipefail preserves ss/head failure; overflow
 # exits without COMPLETE, never a truncated free proof. Host also caps total.
 printf 'BEGIN %s\n' "$token"
 set +e
 output=$(ss -H "$flag" "sport = :${token:1}" | head -c 16385)
 rc=$?
 set -e
 (( ${#output} <= 16384 )) || { printf 'OVERFLOW\n'; exit 65; }
 printf 'RC %s\n' "$rc"
 if [[ -n $output ]]; then printf '%s\n' "$output"; fi
 printf 'END %s\n' "$token"
 [[ $rc == 0 ]] || exit 66
done
printf 'COMPLETE\n'
