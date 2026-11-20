#!/usr/bin/env bash
set -uo pipefail
export LC_ALL=C
umask 077

usage(){
    cat <<'EOF'
Usage: sudo bash 00-service-harden.sh --role dns|ftp|http|ipcam
          [--allow-ports SPEC] [--apply] [--report-dir DIR]
Audit/backup first. --apply only adds broad inbound UFW allows and never enables UFW.
EOF
}
role=;allow_ports=;apply=false;report_root=/root/tcdc-service-backups
while (($#)); do
    case "$1" in
        -h|--help) usage;exit 0;;
        --apply) apply=true;shift;;
        --role|--allow-ports|--report-dir)
            (($#>=2)) || { usage >&2; exit 2; }
            [[ -n $2 && $2 != --* ]] || { usage >&2; exit 2; }
            case "$1" in --role)role=$2;;--allow-ports)allow_ports=$2;;--report-dir)report_root=$2;;esac
            shift 2;;
        *) usage >&2; exit 2 ;;
    esac
done
case "$role" in
    dns|ftp|http|ipcam) ;;
    *) echo 'ERROR: invalid --role' >&2; exit 2 ;;
esac
((EUID == 0)) || { echo 'Run as root.' >&2; exit 1; }
[[ ! -L $report_root ]] || { echo 'Report root must not be a symlink.' >&2; exit 1; }
mkdir -p -m 700 "$report_root"
read -r owner mode < <(stat -c '%u %a' "$report_root")
((owner == 0 && (8#$mode & 077) == 0)) || { echo 'Report root must be root-owned and private.' >&2; exit 1; }
run=$(mktemp -d "$report_root/${role}.XXXXXXXX")
ss -H -lntup >"$run/listeners.txt" 2>&1||true

backup_path(){
    local path=$1
    if [[ -e $path ]];then
        mkdir -p "$run/backup"
        cp -a --parents "$path" "$run/backup/" 2>/dev/null || echo "WARN: could not copy $path" >&2
    fi
}
case "$role" in
    dns)
        for path in /etc/bind /etc/dnsmasq.conf /etc/dnsmasq.d /etc/unbound /var/cache/bind;do backup_path "$path";done
        if command -v named-checkconf >/dev/null;then named-checkconf >"$run/named-checkconf.txt" 2>&1||true;fi
        grep -RniE 'allow-transfer|allow-update|allow-recursion|version' /etc/bind 2>/dev/null >"$run/bind-security.txt"||true
        if command -v dig >/dev/null;then dig @127.0.0.1 localhost A +time=2 +tries=1 >"$run/local-dig.txt" 2>&1||true;fi
        ;;
    ftp)
        for path in /etc/vsftpd.conf /etc/vsftpd /etc/proftpd /etc/ftpusers;do backup_path "$path";done
        if [[ -r /etc/vsftpd.conf ]];then
            grep -niE '^(anonymous_enable|anon_upload_enable|anon_mkdir_write_enable|local_enable|write_enable|chroot_local_user|allow_writeable_chroot|pasv_enable|pasv_min_port|pasv_max_port|userlist_enable|userlist_deny)' /etc/vsftpd.conf >"$run/vsftpd-security.txt"||true
        fi
        if command -v dpkg >/dev/null && dpkg -s vsftpd >/dev/null 2>&1;then dpkg -V vsftpd >"$run/vsftpd-integrity.txt" 2>&1||true;fi
        ;;
    http|ipcam)
        [[ $role != ipcam ]] || echo 'ipcam is outside OPNsense; host firewall and application controls are critical.' >"$run/perimeter-note.txt"
        for path in /etc/nginx /etc/apache2;do backup_path "$path";done
        if [[ -d /var/www ]];then
            find /var/www -type f -exec sha256sum {} + >"$run/webroot.sha256" 2>/dev/null||true
            find /var/www -type f \( -name '*.php' -o -name '*.py' -o -name '*.sh' \) -mtime -7 -printf '%TY-%Tm-%Td %TH:%TM %u:%g %p\n' >"$run/recent-web-scripts.txt" 2>/dev/null||true
            grep -RniE '(shell_exec|passthru|base64_decode|eval\(|os\.system|subprocess)' /var/www 2>/dev/null >"$run/webshell-leads.txt"||true
        fi
        ;;
esac

if [[ -n $allow_ports ]];then
    IFS=',' read -r -a specs <<<"$allow_ports"
    for spec in "${specs[@]}";do
        [[ $spec =~ ^[0-9]{1,5}(:[0-9]{1,5})?/(tcp|udp)$ ]] || { echo "ERROR: invalid port spec: $spec" >&2; exit 2; }
    done
    if ! $apply;then
        printf 'PLAN ONLY: %s\n' "$allow_ports"
        exit 0
    fi
    command -v ufw >/dev/null || { echo 'ufw is required.' >&2; exit 1; }
    ufw status|grep -q '^Status: active' || { echo 'UFW must already be active.' >&2; exit 1; }
    ufw status numbered >"$run/ufw-before.txt"
    for spec in "${specs[@]}";do
        present=false
        while read -r target action remainder;do
            if [[ $target == "$spec" && $action == ALLOW && $remainder == Anywhere* ]];then present=true;break;fi
        done < <(ufw status)
        if ! $present;then ufw allow "$spec" comment "scored $role service";fi
    done
    ufw status numbered >"$run/ufw-after.txt"
    diff -u "$run/ufw-before.txt" "$run/ufw-after.txt"||true
fi
printf 'Service audit saved: %s\n' "$run"
