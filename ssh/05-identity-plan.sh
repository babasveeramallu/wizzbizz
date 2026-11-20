#!/usr/bin/env bash
set -uo pipefail
umask 077

usage() {
    cat <<'EOF'
Usage: sudo bash 05-identity-plan.sh [--apply]

Plan-only by default. --apply writes isolated sshd drop-ins for:
  PermitRootLogin no
  PermitEmptyPasswords no
  MaxAuthTries 4

It does not remove accounts, rotate passwords, alter protected users, or modify
the main sshd_config. Review the plan and scorer dependencies first.
EOF
    exit "${1:-2}"
}

apply=false
case "${1:-}" in
    '') ;;
    --apply) apply=true ;;
    -h|--help) usage 0 ;;
    *) usage 2 ;;
esac
((EUID == 0)) || { echo 'Run as root.' >&2; exit 1; }
command -v sshd >/dev/null 2>&1 || { echo 'sshd is required.' >&2; exit 1; }
sshd -t || exit 1
report_root=/root/tcdc-ssh-backups/identity
mkdir -p -m 700 "$report_root"
run=$(mktemp -d "$report_root/run.XXXXXXXX")
sshd -T >"$run/sshd-before.txt"

dropin=/etc/ssh/sshd_config.d/00-identity-hardening.conf
content=$'PermitRootLogin no\nPermitEmptyPasswords no\nMaxAuthTries 4\n'
printf 'Planned drop-in: %s\n' "$dropin"
printf '%s' "$content"
if ! $apply; then
    printf 'PLAN ONLY. Add --apply after confirming a replacement administrator SSH path.\n'
    exit 0
fi

[[ ! -L /etc/ssh/sshd_config.d ]] || { echo 'Refusing linked sshd config directory.' >&2; exit 1; }
mkdir -p -m 755 /etc/ssh/sshd_config.d
if [[ -e $dropin ]]; then
    cp -p -- "$dropin" "$dropin.tcdc-prechange"
fi
printf '%s' "$content" >"$dropin"
if ! sshd -t; then
    if [[ -e $dropin.tcdc-prechange ]]; then mv -f -- "$dropin.tcdc-prechange" "$dropin"; else rm -f -- "$dropin"; fi
    echo 'sshd validation failed; the drop-in was restored.' >&2
    exit 1
fi
printf 'Applied. Keep the current SSH session open and open a NEW login before reloading sshd.\n'
printf 'Reload only after validation: systemctl reload ssh  OR systemctl reload sshd.\n'
