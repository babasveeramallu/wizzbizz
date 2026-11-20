#!/usr/bin/env bash
set -uo pipefail
umask 077

report_root=${1:-/root/tcdc-ssh-backups/compliance}
((EUID == 0)) || { echo 'Run as root.' >&2; exit 1; }
[[ ! -L $report_root ]] || { echo 'Report path must not be a link.' >&2; exit 1; }
mkdir -p -m 700 "$report_root"
run=$(mktemp -d "$report_root/run.XXXXXXXX")
result="$run/compliance.tsv"
printf 'CONTROL\tSTATUS\tDETAIL\n' >"$result"

check() {
    local control=$1 expected=$2 actual=$3 detail=$4 status
    if [[ $actual == "$expected" ]]; then status=PASS; else status=FAIL; fi
    printf '%s\t%s\t%s\n' "$control" "$status" "$detail ($actual)" >>"$result"
}

if command -v sshd >/dev/null 2>&1; then
    sshd -t >"$run/sshd-test.txt" 2>&1
    sshd -T >"$run/sshd-effective.txt" 2>&1
    check SSH-RootLogin no "$(awk '$1=="permitrootlogin"{print $2;exit}' "$run/sshd-effective.txt")" 'Root login must not be permitted'
    check SSH-EmptyPasswords no "$(awk '$1=="permitemptypasswords"{print $2;exit}' "$run/sshd-effective.txt")" 'Empty-password SSH login must be disabled'
    check SSH-PAM yes "$(awk '$1=="usepam"{print $2;exit}' "$run/sshd-effective.txt")" 'PAM should remain enabled'
    check SSH-MaxAuthTries 4 "$(awk '$1=="maxauthtries"{print $2;exit}' "$run/sshd-effective.txt")" 'Review against the TCDC account-lockout plan'
fi

if command -v ufw >/dev/null 2>&1; then
    ufw status verbose >"$run/ufw.txt" 2>&1
    if grep -q '^Status: active' "$run/ufw.txt"; then
        printf 'NET-FirewallEnabled\tPASS\tUFW is active\n' >>"$result"
    else
        printf 'NET-FirewallEnabled\tFAIL\tUFW is not active\n' >>"$result"
    fi
fi

if sysctl net.ipv4.conf.all.accept_redirects 2>/dev/null | grep -Eq '= 0$'; then
    printf 'OS-IPv4Redirects\tPASS\tIPv4 redirects are disabled for all interfaces\n' >>"$result"
else
    printf 'OS-IPv4Redirects\tFAIL\tIPv4 redirects require review\n' >>"$result"
fi

if [[ -r /etc/passwd && -r /etc/group ]]; then
    uid0=$(awk -F: '$3==0{print $1}' /etc/passwd | paste -sd, -)
    if [[ $uid0 == root ]]; then
        printf 'ID-UID0\tPASS\tOnly root has UID 0\n' >>"$result"
    else
        printf 'ID-UID0\tFAIL\tUID-0 accounts: %s\n' "$uid0" >>"$result"
    fi
fi

pass=0 fail=0
while IFS=$'\t' read -r control status detail; do
    [[ $status == PASS ]] && pass=$((pass+1))
    [[ $status == FAIL ]] && fail=$((fail+1))
done < <(tail -n +2 "$result")
printf 'PASS=%s\nFAIL=%s\nReport=%s\n' "$pass" "$fail" "$result" >"$run/summary.env"
column -t -s $'\t' "$result" 2>/dev/null || cat "$result"
printf 'Compliance report: %s\n' "$run"
printf 'Controls are explicit TCDC-safe checks, not a claim of full CIS/STIG compliance.\n'
