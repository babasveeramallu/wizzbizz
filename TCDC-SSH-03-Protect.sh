#!/usr/bin/env bash
set -uo pipefail
umask 077

usage() {
    cat >&2 <<'EOF'
Usage:
  sudo bash TCDC-SSH-03-Protect.sh PORT
  sudo bash TCDC-SSH-03-Protect.sh PORT --apply

PORT is required. The script is plan-only unless --apply is the second argument.
EOF
    exit 2
}
port=${1:-}
apply=${2:-}
if [[ $port == --help || $port == -h ]]; then
    usage
fi
if [[ $port == --apply ]]; then
    echo 'ERROR: --apply is a mode flag; supply the SSH port first.' >&2
    echo 'Example: sudo bash TCDC-SSH-03-Protect.sh 22 --apply' >&2
    usage
fi
if (($# < 1 || $# > 2)); then
    usage
fi
[[ $port =~ ^[0-9]{1,5}$ ]] || {
    echo 'ERROR: PORT must be a decimal port number.' >&2
    usage
}
port=$((10#$port))
((port >= 1 && port <= 65535)) || usage
[[ -z $apply || $apply == --apply ]] || usage
((EUID == 0)) || { echo 'Run as root.' >&2; exit 1; }
command -v ss >/dev/null && command -v sshd >/dev/null && command -v ufw >/dev/null ||
    { echo 'ss, sshd, and ufw are required.' >&2; exit 1; }

sshd -t
sshd -T | grep -qx "port $port" ||
    { echo "Port $port is not configured by sshd." >&2; exit 1; }
line=$(ss -H -ltnp | grep -E "[:.]${port}[[:space:]]" | head -n 1)
[[ -n $line ]] || { echo "TCP port $port is not listening." >&2; exit 1; }
[[ $line == *sshd* || $line == *ssh* ]] ||
    { echo "TCP port $port is not owned by sshd: $line" >&2; exit 1; }
ufw status | grep -q '^Status: active' ||
    { echo 'UFW is not active; this script will not enable it.' >&2; exit 1; }

if [[ $apply != --apply ]]; then
    echo "PLAN: allow inbound TCP $port from Any after confirming the SSH scorer."
    exit 0
fi
before=$(mktemp)
ufw status numbered >"$before"
if ufw status | grep -q "^[[:space:]]*$port/tcp"; then
    echo "Existing broad rule for TCP $port is present; no duplicate was added."
else
    ufw allow "$port/tcp" comment 'TCDC SSH'
fi
diff -u "$before" <(ufw status numbered) || true
rm -f "$before"
ufw status numbered
echo 'Verify a new SSH session before closing the existing session.'
