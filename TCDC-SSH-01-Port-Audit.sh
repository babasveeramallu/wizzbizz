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
{
    printf 'PROTOCOL\tLOCAL_ADDRESS\tPROCESS\tCLASSIFICATION\n'
    while IFS= read -r line; do
        netid=${line%%[[:space:]]*}
        read -r state recvq sendq local peer process <<<"$line"
        class=REVIEW
        [[ $process == *sshd* || $process == *ssh* ]] && class=SCORED-SSH
        [[ $process == *systemd-resolved* ]] && class=SYSTEM-REVIEW
        printf '%s\t%s\t%s\t%s\n' "$netid" "$local" "${process:-unknown}" "$class"
    done <"$run/listeners.txt"
} >"$run/listener-segmentation.tsv"
printf 'SSH port audit: %s\n' "$run/listener-segmentation.tsv"
column -t -s $'\t' "$run/listener-segmentation.tsv" 2>/dev/null || cat "$run/listener-segmentation.tsv"
printf 'Review every REVIEW listener before changing the firewall.\n'
