#!/usr/bin/env bash
set -uo pipefail
umask 077

report_root=${1:-/root/tcdc-ssh-backups/ports}
((EUID == 0)) || { echo 'Run as root.' >&2; exit 1; }
command -v ss >/dev/null || { echo 'ss is required.' >&2; exit 1; }
[[ ! -L $report_root ]] || { echo 'Report path must not be a link.' >&2; exit 1; }
mkdir -p -m 700 "$report_root"
run=$(mktemp -d "$report_root/run.XXXXXXXX")
ss -H -lntup >"$run/listeners.txt"
socket_active=false
if systemctl is-active --quiet ssh.socket 2>/dev/null; then
    socket_active=true
fi
ssh_ports=()
if command -v sshd >/dev/null 2>&1; then
    while read -r key value; do
        [[ $key == port ]] && ssh_ports+=("$value")
    done < <(sshd -T 2>/dev/null)
fi
{
    printf 'PROTOCOL\tLOCAL_ADDRESS\tPROCESS\tCLASSIFICATION\n'
    while IFS= read -r line; do
        read -r netid state recvq sendq local peer process <<<"$line"
        class=REVIEW
        [[ $process == *sshd* || $process == *ssh* ]] && class=SCORED-SSH
        if $socket_active && [[ $process == *systemd* ]]; then
            for ssh_port in "${ssh_ports[@]}"; do
                if [[ $local == *":$ssh_port" ]]; then class=SCORED-SSH; break; fi
            done
        fi
        [[ $process == *systemd-resolved* ]] && class=SYSTEM-REVIEW
        printf '%s\t%s\t%s\t%s\n' "$netid" "$local" "${process:-unknown}" "$class"
    done <"$run/listeners.txt"
} >"$run/listener-segmentation.tsv"
printf 'SSH port audit: %s\n' "$run/listener-segmentation.tsv"
column -t -s $'\t' "$run/listener-segmentation.tsv" 2>/dev/null || cat "$run/listener-segmentation.tsv"
printf 'Review every REVIEW listener before changing the firewall.\n'
