#!/usr/bin/env bash
set -uo pipefail
export LC_ALL=C
umask 077

usage() {
    cat <<'EOF'
Run on the jumpbox. Pull verified Linux backups into the jumpbox vault.

Usage:
  bash jumpbox-pull-backups.sh --team NUMBER [--user USER]
       [--host NAME|all] [--vault-dir DIR] [--extra-path PATH ...]

Hosts: ns1, ftp-archive, ssh-workstation, artifactorium, ipcam, all
EOF
}

team=
ssh_user=washington
target_host=all
vault_dir="$HOME/tcdc-vault"
extra_paths=()
while (($#)); do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        --team|--user|--host|--vault-dir|--extra-path)
            (($# >= 2)) || { printf 'ERROR: %s requires a value.\n' "$1" >&2; exit 2; }
            [[ -n $2 && $2 != --* ]] || { printf 'ERROR: invalid value for %s.\n' "$1" >&2; exit 2; }
            case "$1" in
                --team) team=$2 ;;
                --user) ssh_user=$2 ;;
                --host) target_host=$2 ;;
                --vault-dir) vault_dir=$2 ;;
                --extra-path) extra_paths+=("$2") ;;
            esac
            shift 2
            ;;
        *) printf 'ERROR: unknown option: %s\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
done

if [[ ! $team =~ ^[0-9]{1,2}$ ]] || ((10#$team < 1 || 10#$team > 99)); then
    printf 'ERROR: --team must be 1-99.\n' >&2
    exit 2
fi
team=$((10#$team))
base=$((100 + team))
for cmd in ssh scp sha256sum mkdir mktemp date tar; do
    command -v "$cmd" >/dev/null 2>&1 || { printf 'ERROR: missing command: %s\n' "$cmd" >&2; exit 1; }
done

declare -A host_ip=(
    [ns1]="10.${base}.10.53"
    [ftp-archive]="10.${base}.10.21"
    [ssh-workstation]="10.${base}.10.22"
    [artifactorium]="10.${base}.10.80"
    [ipcam]="10.150.0.${team}"
)
if [[ $target_host == all ]]; then
    hosts=(ipcam ns1 ftp-archive ssh-workstation artifactorium)
elif [[ -n ${host_ip[$target_host]:-} ]]; then
    hosts=("$target_host")
else
    printf 'ERROR: unknown host: %s\n' "$target_host" >&2
    exit 2
fi

[[ ! -L $vault_dir ]] || { printf 'ERROR: vault must not be a symlink.\n' >&2; exit 1; }
mkdir -p -m 700 "$vault_dir"
mkdir -p -m 700 "$HOME/.ssh"
ctl_dir=$(mktemp -d "$HOME/.ssh/tcdc-backup-control.XXXXXXXX") || exit 1
chmod 700 "$ctl_dir"
trap 'rm -rf -- "$ctl_dir"' EXIT

remote_script='
set -u
umask 077
host=$1; timestamp=$2; owner=$3; stage_dir=$4; shift 4
local_dir=/root/tcdc-local-backups
archive="$local_dir/${host}-${timestamp}.tar.gz"
hash_file="${archive}.sha256"
mkdir -p -m 700 "$local_dir" "$stage_dir"
existing=()
for path in "$@"; do
    [[ -e "$path" ]] && existing+=("$path")
done
((${#existing[@]} > 0)) || { echo "ERROR: none of the requested paths exist" >&2; exit 1; }
temporary="${archive}.partial"
rm -f -- "$temporary"
if ! tar --warning=no-file-changed \
    --exclude="*/ossec*" --exclude="*/wazuh*" \
    -czf "$temporary" "${existing[@]}"; then
    rm -f -- "$temporary"
    echo "ERROR: tar failed; no archive was retained" >&2
    exit 1
fi
mv -- "$temporary" "$archive"
chmod 600 "$archive"
(cd "$local_dir" && sha256sum "${archive##*/}" > "${hash_file##*/}")
chmod 600 "$hash_file"
cp -f -- "$archive" "$stage_dir/"
cp -f -- "$hash_file" "$stage_dir/"
chown "$owner":"$owner" "$stage_dir/${archive##*/}" "$stage_dir/${hash_file##*/}" 2>/dev/null ||
    chown "$owner" "$stage_dir/${archive##*/}" "$stage_dir/${hash_file##*/}"
chmod 600 "$stage_dir/${archive##*/}" "$stage_dir/${hash_file##*/}"
echo "[REMOTE] Local backup saved: $archive"
'

timestamp=$(date +%Y%m%d-%H%M%S)
failures=0
for host in "${hosts[@]}"; do
    ip=${host_ip[$host]}
    destination="$vault_dir/$host"
    mkdir -p -m 700 "$destination"
    control="$ctl_dir/${host}.sock"
    ssh_options=(-o ControlMaster=auto -o "ControlPath=$control" -o ControlPersist=120 -o ConnectTimeout=10)

    paths=(/etc/ssh /etc/passwd /etc/group /etc/sudoers /etc/sudoers.d /etc/ufw
        /etc/cron.d /etc/crontab /etc/hosts /etc/systemd/system)
    case "$host" in
        ns1) paths+=(/etc/bind /etc/named /etc/dnsmasq.conf /etc/dnsmasq.d /etc/unbound /var/cache/bind) ;;
        ftp-archive) paths+=(/etc/vsftpd.conf /etc/vsftpd /etc/proftpd /srv/ftp /var/ftp) ;;
        artifactorium|ipcam) paths+=(/etc/nginx /etc/apache2 /var/www) ;;
    esac
    paths+=("${extra_paths[@]}")

    printf '\n=== %s (%s) ===\n' "$host" "$ip"
    escaped_paths=()
    for path in "${paths[@]}"; do
        escaped_paths+=("$(printf '%q' "$path")")
    done

    if ! ssh -t "${ssh_options[@]}" "${ssh_user}@${ip}" \
        "mkdir -p -m 700 \"\$HOME/.tcdc-stage\" && sudo bash -c $(printf '%q' "$remote_script") _ $(printf '%q' "$host") $(printf '%q' "$timestamp") $(printf '%q' "$ssh_user") \"\$HOME/.tcdc-stage\" ${escaped_paths[*]}"; then
        printf '[WARN] Remote backup failed: %s\n' "$host" >&2
        failures=$((failures + 1))
        continue
    fi

    remote_archive=".tcdc-stage/${host}-${timestamp}.tar.gz"
    remote_hash="$remote_archive.sha256"
    if scp "${ssh_options[@]}" \
        "${ssh_user}@${ip}:$remote_archive" \
        "${ssh_user}@${ip}:$remote_hash" \
        "$destination/" &&
        (cd "$destination" && sha256sum -c "${host}-${timestamp}.tar.gz.sha256"); then
        printf '[OK] Verified vault copy: %s/%s-%s.tar.gz\n' "$destination" "$host" "$timestamp"
    else
        printf '[WARN] Pull or verification failed: %s\n' "$host" >&2
        failures=$((failures + 1))
    fi

    ssh "${ssh_options[@]}" "${ssh_user}@${ip}" \
        "rm -f -- \"\$HOME/.tcdc-stage/${host}-${timestamp}.tar.gz\" \"\$HOME/.tcdc-stage/${host}-${timestamp}.tar.gz.sha256\"" \
        2>/dev/null || true
    ssh -O exit -o "ControlPath=$control" "${ssh_user}@${ip}" 2>/dev/null || true
done

printf '\nVault: %s\nFailures: %d\n' "$vault_dir" "$failures"
((failures == 0))
