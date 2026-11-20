#!/usr/bin/env bash
set -uo pipefail
export LC_ALL=C
umask 077

report_root=/root/tcdc-ssh-backups/vuln-scan
[[ ${1:-} == --report-dir ]] && { [[ -n ${2:-} && ${2} != --* ]] || exit 2; report_root=$2; shift 2; }
(($#==0)) || { echo 'Usage: sudo bash 01-vuln-scan.sh [--report-dir DIR]' >&2; exit 2; }
((EUID==0)) || { echo 'ERROR: run as root.' >&2; exit 1; }
[[ ! -L $report_root ]] || { echo 'ERROR: report root must not be a symlink.' >&2; exit 1; }
mkdir -p -m 700 "$report_root"
read -r owner mode < <(stat -c '%u %a' "$report_root")
((owner==0 && (8#$mode & 077)==0)) || { echo 'ERROR: report root must be private.' >&2; exit 1; }
run=$(mktemp -d "$report_root/run.XXXXXXXX")
findings="$run/findings.tsv"
printf 'SEVERITY\tCHECK\tDETAIL\n' >"$findings"
add_finding(){ local detail=${3//$'\t'/ };detail=${detail//$'\n'/ | };printf '%s\t%s\t%s\n' "$1" "$2" "$detail">>"$findings"; }

{
    [[ -r /etc/sudoers ]] && grep -nvE '^[[:space:]]*(#|$|Defaults)' /etc/sudoers 2>/dev/null | sed 's|^|/etc/sudoers:|'
    [[ -d /etc/sudoers.d ]] && grep -RnvE '^[[:space:]]*(#|$|Defaults)' /etc/sudoers.d 2>/dev/null
} >"$run/sudoers-rules.txt" || true
while IFS= read -r line;do
    [[ -n $line ]]||continue
    if [[ $line == *NOPASSWD* ]];then add_finding HIGH Sudoers-NOPASSWD "$line"
    elif [[ $line == *'(ALL'* && $line != *'%sudo'* && $line != *'%admin'* && $line != *'root'* ]];then add_finding MEDIUM Sudoers-Rule "$line";fi
done <"$run/sudoers-rules.txt"

if command -v getcap >/dev/null;then
    getcap -r / 2>/dev/null >"$run/capabilities.txt"||true
    while IFS= read -r line;do
        [[ -n $line ]]||continue
        if [[ $line =~ cap_(setuid|setgid|dac_override|dac_read_search|sys_admin|sys_ptrace|chown|fowner) ]];then add_finding CRITICAL DangerousCapability "$line"
        else add_finding INFO Capability "$line";fi
    done <"$run/capabilities.txt"
fi

gtfobins='^(ash|awk|base64|bash|busybox|cat|chmod|chown|cp|curl|dash|dd|find|git|gdb|less|lua|make|more|mv|nano|nc|node|openssl|perl|php|python3?|ruby|sed|socat|tar|tee|vim|wget|xargs|xxd|zip)$'
find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -printf '%M %u:%g %p\n' 2>/dev/null >"$run/suid-sgid.txt"
while read -r perms owner_group path;do
    [[ -n $path ]]||continue
    base=${path##*/}
    [[ $base =~ $gtfobins ]] && add_finding CRITICAL GTFOBins-SUID "$perms $owner_group $path"
done <"$run/suid-sgid.txt"

for group in docker lxd lxc disk shadow adm video staff;do
    members=$(getent group "$group" 2>/dev/null|awk -F: '{print $4}')
    if [[ -n $members ]];then
        severity=MEDIUM;[[ $group =~ ^(docker|lxd|lxc|disk|shadow)$ ]]&&severity=HIGH
        add_finding "$severity" DangerousGroup "$group members: $members"
    fi
done

if [[ -s /etc/ld.so.preload ]];then add_finding CRITICAL LD-Preload "/etc/ld.so.preload is non-empty";fi
for file in /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers /etc/crontab /etc/ssh/sshd_config;do
    [[ -e $file ]]||continue
    mode=$(stat -c '%a' "$file")
    other=$((10#${mode: -1}))
    ((other & 2)) && add_finding CRITICAL WorldWritableSystemFile "$file has mode $mode"
    if [[ $file == /etc/shadow || $file == /etc/gshadow ]] && ((other & 4));then add_finding CRITICAL WorldReadableShadow "$file has mode $mode";fi
done

IFS=: read -r -a path_dirs <<<"$PATH"
for directory in "${path_dirs[@]}";do
    [[ -d $directory ]]||continue
    if find "$directory" -maxdepth 0 -perm -0002 ! -perm -1000 -print -quit 2>/dev/null|grep -q .;then
        add_finding HIGH WritablePathDir "$directory"
    fi
done
find /etc/cron* /etc/systemd/system /opt /var/www -xdev -type f -perm -0002 2>/dev/null >"$run/world-writable-sensitive.txt"||true
while IFS= read -r file;do [[ -n $file ]]&&add_finding HIGH WorldWritableFile "$file";done <"$run/world-writable-sensitive.txt"

if [[ -r /etc/exports ]] && grep -q 'no_root_squash' /etc/exports;then add_finding HIGH NFS-NoRootSquash 'no_root_squash is configured';fi
if [[ -r /etc/shadow ]];then
    empty=$(awk -F: '$2==""||$2=="::"{print $1}' /etc/shadow|paste -sd, -)
    [[ -n $empty ]]&&add_finding CRITICAL EmptyPasswordAccount "Accounts: $empty"
fi
add_finding INFO KernelVersion "$(uname -r) ($(uname -m))"
if command -v apt >/dev/null;then
    apt list --upgradable 2>/dev/null|grep -i security >"$run/security-updates.txt"||true
    count=$(wc -l <"$run/security-updates.txt")
    ((count>0))&&add_finding MEDIUM PendingSecurityUpdates "$count security package(s) listed locally"
fi

column -t -s $'\t' "$findings" 2>/dev/null||cat "$findings"
printf 'Full report: %s\n' "$run"
