#!/usr/bin/env bash
set -uo pipefail
umask 077

usage(){ echo 'Usage: sudo bash 08-password-rotation.sh USER [USER ...] [--apply]' >&2; exit 2; }
apply=false
accounts=()
while (($#)); do
    case "$1" in
        --apply) apply=true ;;
        -h|--help) usage ;;
        --*) usage ;;
        *) accounts+=("$1") ;;
    esac
    shift
done
((${#accounts[@]} > 0)) || usage
((EUID == 0)) || { echo 'Run as root.' >&2; exit 1; }
protected='blackteam whiteteam root'
mapfile -t accounts < <(printf '%s\n' "${accounts[@]}" | sort -u)
command -v chpasswd >/dev/null 2>&1 || { echo 'chpasswd is required.' >&2; exit 1; }
for account in "${accounts[@]}"; do
    getent passwd "$account" >/dev/null || { echo "Unknown user: $account" >&2; exit 1; }
    [[ " $protected " != *" $account "* ]] || { echo "Protected account cannot be rotated: $account" >&2; exit 1; }
done

report=/root/tcdc-ssh-backups/password-rotation
command -v stat >/dev/null 2>&1 || { echo 'stat is required.' >&2; exit 1; }
[[ ! -L /root/tcdc-ssh-backups ]] || { echo 'Backup root must not be a symlink.' >&2; exit 1; }
[[ ! -L $report ]] || { echo 'Credential report path must not be a symlink.' >&2; exit 1; }
mkdir -p -m 700 "$report"
read -r owner mode < <(stat -c '%u %a' "$report")
((owner == 0 && (8#$mode & 077) == 0)) || { echo 'Credential report path must be root-owned and private.' >&2; exit 1; }
run=$(mktemp -d "$report/run.XXXXXXXX")
printf 'USERNAME\tPASSWORD\tDASHBOARD_SYNC\n' >"$run/credentials.tsv"
for account in "${accounts[@]}"; do
    if [[ $apply == true ]]; then
        password=$(set +o pipefail; LC_ALL=C tr -dc 'A-HJ-NP-Za-km-z2-9!#%^_*' </dev/urandom | head -c 24)
        if printf '%s:%s\n' "$account" "$password" | chpasswd; then
            status=CHANGED
        else
            status=FAILED
        fi
    else
        password=NOT_GENERATED
        status=PLAN_ONLY
    fi
    printf '%s\t%s\tREQUIRED-%s\n' "$account" "$password" "$status" >>"$run/credentials.tsv"
done
chmod 600 "$run/credentials.tsv"
echo "Private credential sheet: $run/credentials.tsv"
echo 'Immediately update https://dash.playtcdc.org/team/passwords for any changed score user.'
echo 'If the scoring check changes fail, restore the previous credential through your approved recovery path.'
