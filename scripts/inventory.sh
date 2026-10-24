#!/bin/sh
# Read-only host inventory for the Go ssh3 -> ssh3-rs cut-over
# (docs/CUTOVER.md §1). Meant to be run by an operator on oracle, gambetta and
# corentin, one host at a time, after Dmitry's OK.
#
# What it does NOT do: it changes nothing (no writes outside stdout, no
# service actions, no signals), runs no interpreter (no Python), starts no
# long-lived process, and reads only small files. Each external command is a
# single bounded invocation; on oracle (952 MB) its footprint is that of
# coreutils/iproute2/systemctl. It prints secrets' FINGERPRINTS, never keys.
#
# Usage: sh inventory.sh [> inventory-$(hostname).txt]
# Optional sudo: run with sudo to see port owners of other users and root
# configs; without it those lines say "not visible".
set -u
LC_ALL=C; export LC_ALL
sec() { printf '\n=== %s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }
cap() { head -c 65536; }   # never print more than 64 KiB per item

sec "host"
uname -a
[ -r /etc/os-release ] && grep -E '^(PRETTY_NAME|VERSION_ID)=' /etc/os-release
printf 'nproc %s\n' "$(nproc 2>/dev/null || echo ?)"
grep -E '^(MemTotal|MemAvailable|SwapTotal|SwapFree):' /proc/meminfo
for f in /sys/kernel/mm/transparent_hugepage/enabled /sys/kernel/mm/transparent_hugepage/defrag; do
    [ -r "$f" ] && printf '%s: %s\n' "$f" "$(cat "$f")"
done
printf 'uptime: %s\n' "$(cut -d' ' -f1 /proc/uptime)s"
printf 'id: %s\n' "$(id)"

sec "UDP sockets (all), with owners where visible"
if have ss; then ss -uanp 2>/dev/null | cap; else echo "ss not available"; fi
sec "TCP listeners, with owners where visible"
if have ss; then ss -tlnp 2>/dev/null | cap; fi

sec "processes that look like ssh3 / sshd / autossh / relays (pid, user, rss KiB, start, cmd)"
# Listed, never matched for action.
ps -eo pid,user,rss,lstart,args 2>/dev/null | awk 'NR==1 || /ssh3|sshd|autossh|tunnel-watchdog|ssh-shim|socat/ && !/awk/' | cap

sec "systemd units mentioning ssh3/autossh/tunnel"
if have systemctl; then
    systemctl list-units --all --no-legend --no-pager 2>/dev/null | grep -Ei 'ssh3|autossh|tunnel' | cap
    for u in $(systemctl list-unit-files --no-legend --no-pager 2>/dev/null | awk '{print $1}' | grep -Ei 'ssh3|autossh|tunnel'); do
        sec "unit $u"
        systemctl cat "$u" --no-pager 2>/dev/null | cap
        systemctl show "$u" -p ActiveState -p SubState -p MainPID -p ExecMainStartTimestamp -p MemoryCurrent -p MemoryPeak -p NRestarts --no-pager 2>/dev/null
    done
fi

sec "containers"
for rt in docker podman; do
    have "$rt" || continue
    "$rt" ps -a --format '{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}' 2>/dev/null | cap
    for c in $("$rt" ps -a --format '{{.Names}}' 2>/dev/null | grep -Ei 'ssh3|autossh|tunnel'); do
        sec "$rt container $c"
        "$rt" inspect -f 'image={{.Config.Image}} restart={{.HostConfig.RestartPolicy.Name}} netmode={{.HostConfig.NetworkMode}} memory={{.HostConfig.Memory}} started={{.State.StartedAt}} restarts={{.RestartCount}}' "$c" 2>/dev/null
        "$rt" inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$c" 2>/dev/null | grep -Ev -i 'key|secret|token|pass' | cap
        "$rt" inspect -f '{{range .Mounts}}{{.Source}} -> {{.Destination}} ({{.Mode}}){{println}}{{end}}' "$c" 2>/dev/null
    done
done

sec "binaries"
for b in /usr/local/bin/ssh3 /usr/local/bin/ssh3-server /usr/bin/ssh3 /usr/bin/ssh3-server \
         /usr/local/lib/ssh3-test/ssh3-server "$HOME/go/bin/ssh3" "$HOME/go/bin/ssh3-server"; do
    [ -e "$b" ] || continue
    printf '%s %s bytes sha256 %s\n' "$b" "$(wc -c < "$b")" "$(sha256sum "$b" | cut -d' ' -f1)"
done

sec "ssh3 configs and pins (fingerprints only)"
for d in /etc/ssh3 /etc/ssh3-test "$HOME/.ssh3"; do
    [ -d "$d" ] || continue
    ls -la "$d" 2>/dev/null
    for f in "$d"/*; do
        case "$f" in
            *.toml|*.yaml|*.yml|*.conf) sec "file $f"; grep -Ev -i 'key *=|secret|token|pass' "$f" 2>/dev/null | cap ;;
            *known_hosts*|*authorized*) sec "file $f (host/key names only)"; awk '{print $1, $2}' "$f" 2>/dev/null | cap ;;
        esac
    done
done
for k in /etc/ssh/ssh_host_*_key.pub; do
    [ -r "$k" ] && ssh-keygen -lf "$k" 2>/dev/null
done

sec "nginx/hostbeat port allocations referencing forwarded ports"
[ -r /etc/hostbeat/hosts.json ] && cap < /etc/hostbeat/hosts.json
if [ -d /etc/nginx ]; then grep -RhoE 'proxy_pass[^;]*127\.0\.0\.1:[0-9]+' /etc/nginx 2>/dev/null | sort -u | cap; fi

sec "cgroup v2 memory of this shell's slice (for budget planning)"
[ -r /sys/fs/cgroup/cgroup.controllers ] && printf 'controllers: %s\n' "$(cat /sys/fs/cgroup/cgroup.controllers)"
echo "done"
