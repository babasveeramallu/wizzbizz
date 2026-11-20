#!/usr/bin/env bash
set -uo pipefail
export LC_ALL=C
umask 077

usage() {
    cat <<'EOF'
Usage: sudo bash 00-System-Audit.sh [--report-dir DIR]

Read-only first response audit. Captures host identity, interfaces, addresses,
routes, DNS, neighbors, firewall, listeners, connections, users, SSH, services,
timers, persistence metadata, packages, and a bounded auth-log tail.
It never prints private-key material, password hashes, environment variables,
shell history, or raw authorized_keys.
EOF
}

report_root=/root/tcdc-ssh-backups/system-audit
while (($#)); do
    case "$1" in
        --report-dir)
            (($# >= 2)) || { usage; exit 2; }
            [[ -n $2 && $2 != --* ]] || { usage; exit 2; }
            report_root=$2
            shift 2
            ;;
        -h|--help) usage; exit 0 ;;
        *) usage; exit 2 ;;
    esac
done

((EUID == 0)) || { echo 'ERROR: run as root with sudo.' >&2; exit 1; }
for cmd in mkdir mktemp stat hostname date uname cat ip ss ps getent systemctl journalctl find grep; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "ERROR: required command missing: $cmd" >&2; exit 1; }
done

[[ ! -L $report_root ]] || { echo 'ERROR: report path must not be a link.' >&2; exit 1; }
mkdir -p -m 700 "$report_root" || exit 1
read -r owner mode < <(stat -c '%u %a' "$report_root")
((owner == 0 && (8#$mode & 077) == 0)) || {
    echo "ERROR: report path must be root-owned and private: $report_root" >&2
    exit 1
}
run=$(mktemp -d "$report_root/run.XXXXXXXX") || exit 1
failures=0

capture() {
    local file=$1
    shift
    if "$@" >"$run/$file" 2>&1; then
        printf '[OK] %s\n' "$file"
    else
        printf '[WARN] %s incomplete\n' "$file" >&2
        failures=$((failures + 1))
    fi
}

{
    printf 'HOSTNAME=%q\n' "$(hostname)"
    printf 'COLLECTED_AT=%q\n' "$(date --iso-8601=seconds)"
    printf 'KERNEL=%q\n' "$(uname -srmo)"
    printf 'UPTIME=%q\n' "$(uptime -p 2>/dev/null || uptime)"
    printf 'TIMEZONE=%q\n' "$(timedatectl show -p Timezone --value 2>/dev/null || true)"
    printf 'NTP_SYNC=%q\n' "$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)"
    cat /etc/os-release 2>/dev/null
} >"$run/system.txt"

capture addresses.txt ip -brief address
capture routes-v4.txt ip -4 route show table all
capture routes-v6.txt ip -6 route show table all
capture neighbors.txt ip neighbor
capture interfaces.txt ip -details link
if command -v resolvectl >/dev/null 2>&1; then
    capture dns-resolver.txt resolvectl status
else
    capture dns-resolver.txt cat /etc/resolv.conf
fi
capture hosts.txt grep -vE '^[[:space:]]*(#|$)' /etc/hosts
capture listening.txt ss -H -lntup
capture established.txt ss -H -tnp state established
capture all-sockets.txt ss -H -tunap
capture processes.txt ps -eo pid,ppid,user,stat,lstart,args --sort=pid
capture arp.txt ip neighbor

if command -v ufw >/dev/null 2>&1; then
    capture firewall-ufw.txt ufw status verbose
fi
if command -v nft >/dev/null 2>&1; then
    capture firewall-nft.txt nft list ruleset
fi
if command -v iptables-save >/dev/null 2>&1; then
    capture firewall-iptables.txt iptables-save
fi

capture passwd.txt getent passwd
capture group.txt getent group
capture sudo-group.txt getent group sudo
capture wheel-group.txt getent group wheel
capture running-services.txt systemctl list-units --type=service --state=running --no-pager
capture enabled-units.txt systemctl list-unit-files --state=enabled --no-pager
capture failed-units.txt systemctl --failed --no-pager
capture timers.txt systemctl list-timers --all --no-pager
capture mounts.txt findmnt
capture block-devices.txt lsblk -f
capture disk-usage.txt df -h

{
    printf 'SSH_EFFECTIVE_CONFIG\n'
    if command -v sshd >/dev/null 2>&1; then
        sshd -T
        sshd -t
    else
        echo 'sshd not found'
    fi
    printf '\nAUTHORIZED_KEY_FINGERPRINTS\n'
    while IFS=: read -r name _ uid _ _ home shell; do
        [[ $uid =~ ^[0-9]+$ ]] || continue
        for key in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
            if [[ -r $key ]] && command -v ssh-keygen >/dev/null 2>&1; then
                printf '%s owner=%s mode=' "$key" "$(stat -c '%U:%G' "$key")"
                stat -c '%a' "$key"
                ssh-keygen -lf "$key" 2>/dev/null || true
            fi
        done
    done </etc/passwd
} >"$run/ssh-audit.txt" 2>&1

{
    for path in /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily \
        /etc/cron.weekly /etc/cron.monthly /var/spool/cron /etc/systemd/system \
        /etc/xdg/autostart /etc/profile.d /etc/rc.local; do
        [[ -e $path ]] && find "$path" -maxdepth 3 -type f -printf '%M %u:%g %TY-%Tm-%TdT%TH:%TM:%TS %p\n'
    done
} >"$run/persistence-metadata.txt" 2>&1

if command -v dpkg >/dev/null 2>&1; then
    capture packages.txt dpkg-query -W -f='${binary:Package}\t${Version}\n'
elif command -v rpm >/dev/null 2>&1; then
    capture packages.txt rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n'
fi

for log in /var/log/auth.log /var/log/secure /var/log/syslog /var/log/messages; do
    if [[ -r $log ]]; then
        tail -n 500 "$log" >"$run/$(basename "$log").tail.txt"
    fi
done

{
    printf 'CapturedAt=%s\n' "$(date --iso-8601=seconds)"
    printf 'Hostname=%s\n' "$(hostname)"
    printf 'ReportDirectory=%s\n' "$run"
    printf 'Failures=%s\n' "$failures"
    printf 'PrimaryIPv4=%s\n' "$(ip -4 -o addr show scope global | awk 'NR==1 {print $4; exit}')"
    printf 'DefaultGateway=%s\n' "$(ip -4 route show default | awk 'NR==1 {print $3; exit}')"
} >"$run/summary.env"

printf 'Detailed system audit: %s\n' "$run"
printf 'Review system.txt, addresses.txt, routes-v4.txt, listening.txt, dns-resolver.txt, and ssh-audit.txt first.\n'
printf 'No passwords, key material, environment variables, or shell history were collected.\n'
((failures == 0))
