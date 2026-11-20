#!/usr/bin/env bash
set -uo pipefail
umask 077

usage() {
    cat <<'EOF'
Usage: sudo bash 02-Persistence-Audit.sh [--report-dir DIR]
Audit only. No units, cron files, keys, or accounts are changed.
EOF
}

report_root=/root/tcdc-ssh-backups/persistence
while (($#)); do
    case "$1" in
        --report-dir)
            (($# >= 2)) || { usage; exit 2; }
            [[ -n $2 && $2 != --* ]] || { usage; exit 2; }
            report_root=$2
            shift 2
            ;;
        --help|-h) usage; exit 0 ;;
        *) usage; exit 2 ;;
    esac
done

((EUID == 0)) || { echo 'Run as root.' >&2; exit 1; }
[[ ! -L $report_root ]] || { echo 'Report path must not be a link.' >&2; exit 1; }
mkdir -p -m 700 "$report_root"
run=$(mktemp -d "$report_root/run.XXXXXXXX")

{
    for path in /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily \
        /etc/cron.weekly /etc/cron.monthly /var/spool/cron /etc/systemd/system; do
        [[ -e $path ]] && find "$path" -maxdepth 3 -type f -printf '%M %u:%g %p\n'
    done
} >"$run/persistence-files.txt" 2>&1
systemctl list-timers --all --no-pager >"$run/timers.txt" 2>&1
systemctl list-unit-files --state=enabled --no-pager >"$run/enabled-units.txt" 2>&1
find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -printf '%M %u:%g %p\n' 2>/dev/null >"$run/suid-sgid.txt"
{
    for path in /etc/sudoers /etc/sudoers.d /etc/pam.d /etc/profile /etc/profile.d \
        /etc/ld.so.preload; do
        [[ -e $path ]] && find "$path" -maxdepth 2 -type f -printf '%M %u:%g %TY-%Tm-%TdT%TH:%TM:%TS %p\n' 2>/dev/null
    done
} >"$run/security-config-metadata.txt"
grep -RniE '^[[:space:]]*(AuthorizedKeysCommand|AuthorizedKeysCommandUser)[[:space:]]' \
    /etc/ssh 2>/dev/null >"$run/authorized-keys-command.txt" || true

while IFS=: read -r name _ uid _ _ home shell; do
    [[ $uid =~ ^[0-9]+$ ]] || continue
    if command -v crontab >/dev/null; then crontab -u "$name" -l 2>/dev/null || true; fi
    for key in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
        if [[ -r $key ]] && command -v ssh-keygen >/dev/null; then
            printf '%s\n' "$key"
            ssh-keygen -lf "$key"
        fi
    done
done </etc/passwd >"$run/user-persistence.txt" 2>&1

printf 'Persistence audit: %s\n' "$run"
printf 'Audit only; no units, cron files, keys, or accounts were changed.\n'
