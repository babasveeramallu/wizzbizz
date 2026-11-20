#!/usr/bin/env bash
set -uo pipefail
umask 077

usage() {
    cat <<'EOF'
Usage: sudo bash 07-Wazuh-Verify.sh [--manager-host DNS] [--manager-ip IP] [--allow-firewall] [--report-dir DIR]

Read-only by default. It checks the existing Black Team-managed agent, manager
DNS, local agent log, and outbound TCP 1514. It never installs, enrolls,
restarts, or edits Wazuh.
Black Team confirms one managed, pre-enrolled agent exists per competition host.
A separate team-managed agent is allowed only with different ports and completely
separate files, service identity, and configuration. This tool only checks the
managed agent; it does not deploy the independent instance.

--manager-host DNS  Manager name (default: wazuh.blackteam.playtcdc.org).
--manager-ip IP     Exact IPv4 to probe or use for an exact firewall rule.
--allow-firewall    Add one UFW outbound allow only when --manager-ip is used.
--report-dir DIR    Protected report root (default: /root/tcdc-wazuh-verification).
EOF
}

manager_host=wazuh.blackteam.playtcdc.org
manager_ip=
allow_firewall=false
report_root=/root/tcdc-wazuh-verification
while (($#)); do
    case "$1" in
        --help|-h) usage; exit 0 ;;
        --allow-firewall) allow_firewall=true; shift ;;
        --manager-host|--manager-ip|--report-dir)
            (($# >= 2)) || { printf 'ERROR: %s requires a value.\n' "$1" >&2; exit 2; }
            [[ -n $2 && $2 != --* ]] || { printf 'ERROR: invalid value for %s.\n' "$1" >&2; exit 2; }
            case "$1" in
                --manager-host) manager_host=$2 ;;
                --manager-ip) manager_ip=$2 ;;
                --report-dir) report_root=$2 ;;
            esac
            shift 2
            ;;
        *) printf 'ERROR: unknown option %s\n' "$1" >&2; exit 2 ;;
    esac
done

if [[ -n $manager_ip ]]; then
    if [[ ! $manager_ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        printf 'ERROR: manager IP must be one IPv4 address.\n' >&2
        exit 2
    fi
    IFS=. read -r a b c d <<<"$manager_ip"
    for octet in "$a" "$b" "$c" "$d"; do
        ((10#$octet <= 255)) || { printf 'ERROR: invalid IPv4 address.\n' >&2; exit 2; }
    done
    printf -v manager_ip '%d.%d.%d.%d' "$((10#$a))" "$((10#$b))" "$((10#$c))" "$((10#$d))"
fi
if $allow_firewall && [[ -z $manager_ip ]]; then
    printf 'ERROR: --allow-firewall requires --manager-ip for an exact destination.\n' >&2
    exit 2
fi
((EUID == 0)) || { printf 'ERROR: run as root with sudo.\n' >&2; exit 1; }

for cmd in mkdir mktemp stat cp timeout date getent systemctl journalctl; do
    command -v "$cmd" >/dev/null 2>&1 || { printf 'ERROR: required command missing: %s\n' "$cmd" >&2; exit 1; }
done
[[ ! -L $report_root ]] || { printf 'ERROR: report root must not be a link.\n' >&2; exit 1; }
mkdir -p -m 700 -- "$report_root" || exit 1
read -r owner mode < <(stat -c '%u %a' -- "$report_root")
((owner == 0 && (8#$mode & 077) == 0)) || {
    printf 'ERROR: report root must be root-owned and private: %s\n' "$report_root" >&2
    exit 1
}
run=$(mktemp -d "$report_root/run.XXXXXXXX") || exit 1
failures=0

systemctl list-units --all --no-pager wazuh-agent.service wazuh.service ossec.service >"$run/agent-services.txt" 2>&1 ||
    failures=$((failures + 1))
active_agent=false
for unit in wazuh-agent.service wazuh.service ossec.service; do
    if systemctl is-active --quiet "$unit"; then active_agent=true; break; fi
done
if [[ $active_agent != true ]]; then
    printf 'WARN: no Wazuh service is active: %s\n' "$manager_host" >&2
    failures=$((failures + 1))
fi
systemctl list-unit-files --no-pager wazuh-agent.service wazuh.service ossec.service >>"$run/agent-services.txt" 2>&1 ||
    true
journalctl -u wazuh-agent.service -u wazuh.service -u ossec.service \
    --since '24 hours ago' -n 200 --no-pager >"$run/agent-journal.txt" 2>&1 || true

getent ahostsv4 "$manager_host" >"$run/dns.txt" 2>&1 || {
    printf 'DNS resolution failed for %s\n' "$manager_host" >>"$run/dns.txt"
    failures=$((failures + 1))
}
destination=${manager_ip:-$manager_host}
if timeout 5 bash -c 'exec 3<>"/dev/tcp/$1/1514"' _ "$destination" 2>/dev/null; then
    connected=true
else
    connected=false
    failures=$((failures + 1))
fi
printf 'destination=%s:1514\nconnected=%s\nchecked_at=%s\n' \
    "$destination" "$connected" "$(date --iso-8601=seconds)" >"$run/transport.env"

for log in /var/ossec/logs/ossec.log /opt/ossec/logs/ossec.log; do
    if [[ -r $log ]]; then
        tail -n 50 "$log" >"$run/ossec-tail.txt"
        break
    fi
done

rule=
if $allow_firewall; then
    command -v ufw >/dev/null 2>&1 || { printf 'ERROR: UFW is unavailable.\n' >&2; exit 1; }
    ufw status | grep -q '^Status: active' || {
        printf 'ERROR: UFW is not active; this script will not enable it.\n' >&2
        exit 1
    }
    if ! ufw allow out to "$manager_ip" port 1514 proto tcp comment 'Wazuh event transport' \
        >"$run/firewall-change.txt" 2>&1; then
        printf 'ERROR: exact Wazuh firewall rule failed; inspect UFW.\n' >&2
        exit 1
    fi
    rule="outbound-tcp-$manager_ip-1514"
    ufw status numbered >"$run/firewall-after.txt" 2>&1
fi

printf 'report_directory=%s\nmanager_host=%s\nmanager_ip=%s\ntcp1514_connected=%s\nfirewall_rule=%s\nchanged_agent_configuration=false\n' \
    "$run" "$manager_host" "${manager_ip:-}" "$connected" "${rule:-}" >"$run/summary.env"

printf 'Private report: %s\n' "$run"
printf 'Protected baseline: one Black Team-managed, pre-enrolled agent. Do not repoint or reconfigure it.\n'
printf 'An independent agent is allowed only with separate ports, service, files, and configuration.\n'
printf 'TCP 1514 connected: %s\n' "$connected"
printf 'Agent configuration changed: no\n'
printf 'Note: TCP reachability does not prove enrollment or central event receipt.\n'
if [[ $connected != true ]]; then
    printf 'WARN: Check DNS, route, and firewall. Ask Black Team if the agent needs service/configuration work.\n' >&2
fi
((failures == 0))
