#!/usr/bin/env bash
set -uo pipefail
umask 077

if [[ ${1:-} == --compare ]]; then
    baseline=${2:-}
    current=${3:-}
    [[ -n $baseline && -n $current && -d $baseline && -d $current ]] || {
        echo 'Usage: sudo bash 06-Baseline-Compare.sh --compare OLD_RUN NEW_RUN' >&2
        exit 2
    }
    diff -u "$baseline/state.sha256" "$current/state.sha256" || true
    printf 'Firewall diff:\n'
    diff -u "$baseline/firewall.txt" "$current/firewall.txt" || true
    exit 0
fi

report_root=${1:-/root/tcdc-ssh-backups/drift}
((EUID == 0)) || { echo 'Run as root.' >&2; exit 1; }
mkdir -p -m 700 "$report_root"
run=$(mktemp -d "$report_root/run.XXXXXXXX")
{
    sha256sum /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null
    systemctl list-unit-files --state=enabled --no-pager
    find /etc/cron.d /etc/systemd/system -maxdepth 3 -type f -print0 2>/dev/null |
        sort -z | xargs -0 sha256sum 2>/dev/null
} >"$run/state.sha256"
{
    ufw status numbered 2>/dev/null
    nft list ruleset 2>/dev/null
    iptables-save 2>/dev/null
} >"$run/firewall.txt"
ss -H -lntup >"$run/listeners.txt"
getent passwd >"$run/passwd.txt"
printf 'Baseline saved: %s\n' "$run"
