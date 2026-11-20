# Hardening Playbook & Game-Day Runbook

---

## Table of Contents

1. [Schedule, Portals & Key Contacts](#1-schedule-portals--key-contacts)
2. [Rules of Engagement Snapshot](#2-rules-of-engagement-snapshot)
3. [Network Topology & Asset Map](#3-network-topology--asset-map)
4. [Protected Accounts & Password Sync Policy](#4-protected-accounts--password-sync-policy)
5. [5-Person Team Role Split & Runbook Timeline](#5-5-person-team-role-split--runbook-timeline)
6. [Anonymous Repo Pull & `wizzbizz` Script Reference](#6-anonymous-repo-pull--wizzbizz-script-reference)
7. [3-Tier Backup Strategy (R23 Compliant)](#7-3-tier-backup-strategy-r23-compliant)
8. [Phase 0: Universal Linux First-5-Minutes Baseline](#8-phase-0-universal-linux-first-5-minutes-baseline)
9. [Playbook 1: `opnsense` & `jumpbox` (Perimeter & Management)](#9-playbook-1-opnsense--jumpbox-perimeter--management)
10. [Playbook 2: `ns1` — DNS (Ubuntu Server 26.04 LTS)](#10-playbook-2-ns1--dns-ubuntu-server-2604-lts)
11. [Playbook 3: `ftp-archive` — FTP (Ubuntu Server 26.04 LTS)](#11-playbook-3-ftp-archive--ftp-ubuntu-server-2604-lts)
12. [Playbook 4: `artifactorium` & `ipcam` — HTTP (Ubuntu Server 26.04 LTS)](#12-playbook-4-artifactorium--ipcam--http-ubuntu-server-2604-lts)
13. [Playbook 5: `ssh-workstation` — SSH (Ubuntu Server 26.04 LTS)](#13-playbook-5-ssh-workstation--ssh-ubuntu-server-2604-lts)
14. [Playbook 6: `ad` — Active Directory (Windows Server 2025)](#14-playbook-6-ad--active-directory-windows-server-2025)
15. [Playbook 7: `mqtt` — Mosquitto (Windows 11 Pro)](#15-playbook-7-mqtt--mosquitto-windows-11-pro)
16. [Wazuh Strategy, Lightweight Monitoring & Drift Checks](#16-wazuh-strategy-lightweight-monitoring--drift-checks)
17. [Emergency Triage & Recovery One-Liners](#17-emergency-triage--recovery-one-liners)
18. [Game-Day Tracking Templates (Passwords, Store, Injects, IR)](#18-game-day-tracking-templates-passwords-store-injects-ir)
19. [Pre-Competition GitHub Hygiene (`.gitignore`)](#19-pre-competition-github-hygiene-gitignore)

---

## 1. Schedule, Portals & Key Contacts

All times are **Central Time (CT)** on **Saturday, November 21, 2026**.

| Time (CT) | Block | Hands-On? | Operational Notes |
| :--- | :--- | :---: | :--- |
| **9:00 AM – 10:00 AM** | Competition Start (1-Hr Grace Period) | **Yes** | Verify access, baseline, observe live scoring checks, rotate creds. |
| **10:00 AM – 12:00 PM** | Morning Competition Block | **Yes** | Complete hardening, deploy monitoring, answer morning injects. |
| **12:00 PM – 1:00 PM** | Lunch Break | **NO (R10)** | **Stop all activity on boxes** (including pausing live loops/dashboards). |
| **1:00 PM – 5:00 PM** | Afternoon Competition Block | **Yes** | Resume drift checks, watch for post-lunch store currency top-up, finish injects. |
| **5:00 PM – 5:45 PM** | Results Tally, Awards & Wrap-Up | **NO (R10)** | Hands off all infrastructure. |
| **5:45 PM** | Competition Ends | **NO** | Final debrief. |

### Official Portals & Contacts

| Resource | URL / Contact |
| :--- | :--- |
| **Scoreboard** | `https://score.playtcdc.org/` |
| **Password Changes (CRITICAL)** | `https://dash.playtcdc.org/team/passwords` |
| **Inject Submissions** | `https://dash.playtcdc.org/team/injects` |
| **Competition Store** | `https://dash.playtcdc.org/team/store` |
| **TxCR Single Sign-On (Xen Orchestra)** | `https://sso.txcr.dev` |

### Scoring & Store Clarifications (Packet + Staff Discord)
- **Weights:** **80% Uptime** / **20% Injects**.
- **Uptime Ticks:** Checked every **30 seconds**. Checkers validate real service responses (not just open ports) and may authenticate with OS or service accounts.
- **Incident Reports (IR):** **No points are refunded** for proving Red Team caused an outage. If an IR inject is assigned at the end of the day, evidence only improves your grade on that inject.
- **Store Currency:** Fixed starting balance for snapshots/reverts, extra console access, or Red Team requests. Staff noted they *may* distribute an equal bonus to all teams after lunch—prioritize saving currency for **snapshots and reverts**.

---

## 2. Rules of Engagement Snapshot

| Rule | Mandate |
| :--- | :--- |
| **R5** | Only the 5 registered competitors may work on team tasks. Alternates **may not** coach, instruct, or guide during competition. |
| **R6 / R9** | Only your 9 topology boxes are in scope for defense (and rival teams' matching boxes for reversible purple teaming). Everything else is out of scope. |
| **R7 / R14 / R15** | **Strictly out of scope:** `blackteam` and `whiteteam` users, **Wazuh** (outbound TCP `1514` → `wazuh.blackteam.playtcdc.org` / `10.100.0.11`), `auditd`, Xen Orchestra, `xe-guestutilities`, `cloud-init`, scoreboard/dashboard, and Discord. Never stop, restart, repoint, impersonate, or overwrite Black Team's Wazuh agent. |
| **R8** | Never change the password of, disable, or remove `blackteam` or `whiteteam`. **Never delete** any listed museum OS user. |
| **R10** | Do nothing on your boxes during hands-off windows (Lunch `12:00–1:00 PM CT` and after `5:00 PM CT`). |
| **R11 – R13** | Purple teaming (if attempted) must be reversible: never brick a box, lock a team out (e.g., disabling Netlogon), or delete critical files without a backup. |
| **R18** | **Network Rules:** Unrestricted rules between your 4 internal subnets (`10.(100+X).10/20/30/40.0/24`). Outside those subnets: **incoming block rules must apply to all source IPs (`*`)**; **outgoing block rules must name 1 exact destination IP and 1 exact port** (no default-deny outbound, no blocking external subnets/ranges). |
| **R19** | No network-level attacks (DoS, ARP spoofing). |
| **R20 / R21** | Custom tools must be free, hosted in a **public repository** (e.g., GitHub), and submitted on the **Tool Links form**. **NO AI USAGE** during competition. |
| **R23 / R25** | **No data exfiltration** from competition infrastructure (**screenshots and passwords are the ONLY exceptions**). **No personal account logins** on competition boxes. |
| **R24** | Test all custom tools outside competition infrastructure before the event. |

---

## 3. Network Topology & Asset Map

Replace `X` with your Team ID. Domain format: `<Hostname>.teamX.playtcdc.org`.  
Team internal `/24` subnets: `10.(100+X).10.0/24` (DMZ), `.20.0/24` (Internal Servers), `.30.0/24` (Users/Workstations), `.40.0/24` (Management).

| Hostname | Subnet / Zone | IP Address | OS | Service | Scored? | Priority Notes |
| :--- | :--- | :--- | :--- | :--- | :---: | :--- |
| `opnsense` | Mgmt / WAN | `10.(100+X).40.1`<br>WAN: `100.64.0.X` | OPNsense 26.7 | Firewall | No | Download XML backup first; restrict GUI/SSH to Mgmt; segment internal subnets. |
| `jumpbox` | Mgmt / VPN | `10.(100+X).40.22`<br>Alt: `10.99.X.2` | Linux Jumpbox | HTTPS `3001–3006` (Chromium)<br>HTTPS `3007–3008` (Remmina RDP) | No | Keep WAN closed (R6 default); primary off-host backup vault. |
| **`ipcam`** | **Public Cloud** (`10.150.0.0/24`) | **`10.150.0.X`** | Ubuntu 26.04 LTS | HTTP (IP Cam SaaS) | **Yes** | **HIGHEST PRIORITY — sits OUTSIDE OPNsense.** Host hardening & UFW are its only firewall. |
| `ns1` | DMZ | `10.(100+X).10.53` | Ubuntu 26.04 LTS | DNS | **Yes** | Back up `/etc/bind`, baseline `dig`, disable AXFR/updates, verify recursion before limiting. |
| `ftp-archive` | DMZ | `10.(100+X).10.21` | Ubuntu 26.04 LTS | FTP | **Yes** | Back up configs & FTP root; check anon vs. user login; **open PASV port range in UFW**. |
| `artifactorium` | DMZ | `10.(100+X).10.80` | Ubuntu 26.04 LTS | HTTP (On-Prem) | **Yes** | Back up webroot & dump DBs; hash web files; hunt web shells; bind DB to `127.0.0.1`. |
| `ssh-workstation` | DMZ | `10.(100+X).10.22` | Ubuntu 26.04 LTS | SSH | **Yes** | Run full Linux `wizzbizz` suite; keep `PasswordAuthentication yes` unless key-only confirmed. |
| `ad` | Internal Servers | `10.(100+X).20.88` | Windows Server 2025 | Active Directory | **Yes** | Audit Domain Admins, rotate AD creds + sync, kill AS-REP/SMBv1/LLMNR/Spooler. |
| `mqtt` | Users / Workstations | `10.(100+X).30.49` | Windows 11 Pro | MQTT (Mosquitto) | **Yes** | Verify listening port & `mosquitto.conf` before `-ApplyHardening`; configure `sc failure`. |

---

## 4. Protected Accounts & Password Sync Policy

### Never Touch (R7 & R8)
- **Do NOT change password, disable, or delete:** `blackteam`, `whiteteam`.

### Listed Museum OS Users (R8 — Never Delete; Rotate Passwords & Sync Immediately)
- **Admins (5):** `washington`, `kennedy`, `teddy`, `lincoln`, `ross`
- **Employees (10):** `streep`, `franklin`, `parks`, `armstrong`, `hamilton`, `mlk`, `tubman`, `manziel`, `deniro`, `bush`
- **Service Accounts:** Additional service-specific accounts (e.g., FTP, DB, Web UI, MQTT `password_file`) may exist on boxes and are not printed in the packet.

### Mandatory Password Rotation Procedure
1. Coordinate with the **Team Captain** before running any password rotation.
2. Rotate passwords on **one box at a time** (never rotate `blackteam` or `whiteteam`).
3. Immediately update the changed password(s) at **`https://dash.playtcdc.org/team/passwords`**.
4. Watch `https://score.playtcdc.org/` for **2–3 ticks (60–90 seconds)** to confirm green checks before moving to the next box.
5. **Never** open `credentials.csv` / `credentials.tsv` in Excel (use Notepad, `cat`, or PowerShell).

---

## 5. 5-Person Team Role Split & Runbook Timeline

### Role Matrix

| Role | Assigned Systems | Primary Responsibilities |
| :--- | :--- | :--- |
| **1. Network & Perimeter Lead** | `opnsense`, `jumpbox` | OPNsense XML backup, rotate firewall/jumpbox creds, Mgmt-only GUI, R18 internal segmentation, Live Firewall Logs, maintain `~/tcdc-vault`. |
| **2. Windows & AD Lead** | `ad`, `mqtt` | AD health & Domain Admin audit, Windows/AD password rotation + sync, MQTT port verification & hardening, `sc failure` recovery, Windows alert dashboard. |
| **3. Linux Core Lead** | `ns1`, `ssh-workstation` | Back up BIND & `/etc/ssh`, rotate creds + sync, harden BIND9 & `00-identity-hardening.conf`, UFW, Wazuh verification, `rsyslog` forwarding. |
| **4. Linux Web & File Lead** | `ipcam` (1st!), `artifactorium`, `ftp-archive` | Lock down cloud `ipcam` first, dump DBs & hash webroots/FTP files, hunt web shells, harden Nginx/Apache/`vsftpd`, open FTP PASV ports. |
| **5. Captain / Injects & Comms Lead** | Dashboard, Injects (`20%`), Store, Scoreboard | Own master password tracker, sync `dash.playtcdc.org/team/passwords`, monitor 30s scoreboard ticks, draft/submit injects ahead of deadlines, manage Store currency. |

### Competition Day Runbook Timeline

- [ ] **Pre-9:00 AM CT:** Confirm VPN, TxCR SSO (`https://sso.txcr.dev`), Discord, and Tool Links form submission (**R20**). Close all AI tools (**R21**).
- [ ] **Min 0–10 (9:00–9:10 AM):** Connect to `jumpbox` (`https://10.99.X.2:3001`–`3008`). Verify all 7 scored services are green on `score.playtcdc.org`. Download OPNsense XML backup. Create `~/tcdc-vault` on `jumpbox` and configure Remmina Shared Folders for `ad` and `mqtt`. Clone `wizzbizz` anonymously (**R25**).
- [ ] **Min 10–25 (9:10–9:25 AM):** Run read-only audits (`00`, `01`, `02`, `06`, `07`) on all hosts. Pull initial off-host backups to `jumpbox` (`ipcam` first!). Watch live logs (`auth.log`, `vsftpd.log`, Nginx/Apache access logs, `mosquitto`) to confirm exact scorer behavior during the grace period.
- [ ] **Min 25–45 (9:25–9:45 AM):** Rotate default OS, AD, OPNsense, and app passwords box-by-box (skip `blackteam`/`whiteteam`). Captain syncs `dash.playtcdc.org/team/passwords` immediately and verifies green ticks.
- [ ] **Min 45–60 (9:45–10:00 AM):** Apply OPNsense R18 inter-subnet blocks, UFW rules (including FTP PASV range), `05-identity-plan.sh --apply`, AD attack-path remediations, and `TCDC-MQTT-Windows-Hardening.ps1 -ApplyHardening -MqttPorts <ports>`. Re-verify all services. Take a post-hardening backup snapshot.
- [ ] **Every 20–30 Min (10:00 AM – 5:00 PM):** Run `06-drift-compare` on Linux/Windows, check `quser` / `who`, watch OPNsense Live View and `10-mqtt-alert-dashboard.ps1`, and track Inject deadlines.
- [ ] **11:55 AM & 4:55 PM CT:** Confirm all 7 services green, stop dashboards/loops (`Ctrl+C`), and go **strictly hands-off** for Lunch (`12:00–1:00 PM`) and End-of-Day (`5:00 PM`) per **R10**.

---

## 6. Anonymous Repo Pull & `wizzbizz` Script Reference

> **R25 Reminder:** Never log into GitHub or personal accounts on competition infrastructure. Clone anonymously over HTTPS only (or pull once onto the `jumpbox` and `scp` internally if a box has no internet egress).

### Pull Commands

```bash
# Linux (ns1, ftp-archive, ssh-workstation, artifactorium, ipcam, jumpbox)
sudo mkdir -p /root/wizzbizz && sudo chmod 700 /root/wizzbizz
sudo git clone https://github.com/babasveeramallu/wizzbizz.git /root/wizzbizz

# Fallback if git is unavailable:
sudo curl -fsSL https://github.com/babasveeramallu/wizzbizz/archive/refs/heads/main.tar.gz -o /root/wizzbizz.tar.gz
sudo tar -xzf /root/wizzbizz.tar.gz -C /root/wizzbizz --strip-components=1
```

```powershell
# Windows (ad, mqtt) — Elevated PowerShell
New-Item -ItemType Directory -Path C:\Tools\wizzbizz -Force | Out-Null
icacls C:\Tools\wizzbizz /inheritance:r /grant:r "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F"
Invoke-WebRequest -Uri "https://github.com/babasveeramallu/wizzbizz/archive/refs/heads/main.zip" -OutFile C:\Tools\wizzbizz.zip
Expand-Archive -Path C:\Tools\wizzbizz.zip -DestinationPath C:\Tools\wizzbizz -Force
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
```

### Finalized `wizzbizz` Script Inventory

| Platform | Script Filename | Mode / Purpose |
| :--- | :--- | :--- |
| **Linux** | `TCDC-SSH-Ubuntu-Audit.sh` | All-in-one SSH audit, `/etc/ssh` backup, topology check, optional UFW allow (`--allow-ssh`, `--allow-wazuh`, `--check-wazuh`). |
| **Linux** | `00-system-audit.sh` | Read-only host, network, firewall, service, user, SSH, and auth-log audit. |
| **Linux** | `01-port-audit.sh` | Segments TCP/UDP listeners (`SCORED-SSH` incl. `ssh.socket`, `SYSTEM-REVIEW`, `REVIEW`). |
| **Linux** | `02-persistence-audit.sh` | Audits cron, systemd, timers, SUID/SGID, `sudoers`, PAM, `ld.so.preload`, `AuthorizedKeysCommand`, and `authorized_keys` fingerprints. |
| **Linux** | `03-protect-scored-service.sh` | Plan-only by default (`PORT --apply`); verifies `sshd -t`, `sshd -T`, active listener/`ssh.socket`, and adds broad UFW allow if missing. |
| **Linux** | `04-compliance-audit.sh` | Checks `PermitRootLogin`, `PermitEmptyPasswords`, `UsePAM`, `MaxAuthTries`, UFW active, IPv4 redirects, UID 0. |
| **Linux** | `05-identity-plan.sh` | Plan-only by default (`--apply`); writes `/etc/ssh/sshd_config.d/00-identity-hardening.conf` (first-match-wins) with `sshd -t` rollback. |
| **Linux** | `06-drift-compare.sh` | Captures and compares `state.sha256`, `firewall.txt`, `passwd.txt`, and PID/FD-stripped `listeners.txt`. |
| **Linux** | `07-wazuh-verify.sh` | Read-only check of Black Team Wazuh units, DNS, local log, and TCP `1514` reachability. |
| **Linux** | `08-password-rotation.sh` | Plan-only by default (`USER... --apply`); skips `blackteam`/`whiteteam`/`root`, uses formula-safe alphabet, checks `chpasswd` exit code. |
| **Windows** | `TCDC-MQTT-Windows-Hardening.ps1` | All-in-one MQTT audit, Mosquitto/FW/evtx backup, optional `-ApplyHardening -MqttPorts <ports>` (refreshes PID if started). |
| **Windows** | `00-system-audit.ps1` | Read-only system, network, listeners, firewall, users/groups, services, tasks, shares, software audit. |
| **Windows** | `01-port-audit.ps1` | Segments TCP/UDP listeners (`SCORED-MQTT`, `SYSTEM-REVIEW`, `REVIEW`). |
| **Windows** | `02-persistence-audit.ps1` | Audits custom tasks, services, WMI subscriptions, Defender exclusions, `quser`, SMB share ACLs, Run/RunOnce keys. |
| **Windows** | `03-protect-scored-service.ps1` | Plan-only by default (`-Port <p> -Apply`); sets Mosquitto `Automatic` and adds `WizzBizz-MQTT-TCP-<p>` inbound allow. |
| **Windows** | `04-compliance-audit.ps1` | Audits firewall profiles, LLMNR disabled, SMBv1 disabled, PowerShell 4104 logging, local admins, Mosquitto state. |
| **Windows** | `05-identity-plan.ps1` | Defaults to `LockoutThreshold=0` (lockout disabled to prevent Red Team checker-lockout DoS). |
| **Windows** | `06-drift-compare.ps1` | Section-by-section drift comparison (`Services`, `Listeners` w/o volatile PIDs, `Firewall`, `Tasks`, `Users`). |
| **Windows** | `07-wazuh-verify.ps1` | Read-only check of managed Wazuh/ossec service, DNS, `ossec.log`, and TCP `1514` reachability. |
| **Windows** | `08-mosquitto-functional-check.ps1` | Backs up `mosquitto.conf`, extracts security/include directives, checks TCP port, optional `-FunctionalTest` anonymous pub/sub. |
| **Windows** | `09-password-rotation.ps1` | Plan-only by default (`-Account ... -Apply`); skips protected accounts, writes incrementally to `icacls`-locked `credentials.csv`. *(Local users only—use `Set-ADAccountPassword` on `ad`.)* |
| **AD** | `ad/00-audit-harden.ps1` | Audits DC identity, groups, delegation, GPOs, SYSVOL, shares, sessions, Wazuh, and selected host controls; optional `-Apply`. |
| **AD** | `ad/01-password-rotation.ps1` | Plan-first AD-native password rotation with protected identities, private incremental CSV, and immediate dashboard-sync reminder. |
| **Linux services** | `linux/00-service-harden.sh` | Audits DNS, FTP, HTTP, or ipcam service configuration and optionally adds confirmed broad inbound UFW rules. |
| **Optional** | `backup/jumpbox-pull-backups.sh` / `backup/windows-dual-backup.ps1` / `mqtt/10-mqtt-alert-dashboard.ps1` | Dual local + jumpbox vault backups and zero-port live Windows MQTT alert dashboard. |

## Active Directory

Run from an elevated PowerShell session on `ad`:

```powershell
.\ad\00-audit-harden.ps1
.\ad\01-password-rotation.ps1 -Account washington,kennedy,teddy
```

## Other Linux Services

Run from the applicable DNS, FTP, HTTP, or ipcam host:

```bash
sudo bash linux/00-service-harden.sh --role dns
sudo bash linux/00-service-harden.sh --role ftp
sudo bash linux/00-service-harden.sh --role http
sudo bash linux/00-service-harden.sh --role ipcam
```

Add `--allow-ports` and `--apply` only after confirming active listeners. UFW
must already be active.

## MQTT

---

## 7. 3-Tier Backup Strategy (R23 Compliant)

Never copy configs, webroots, DB dumps, or `/etc/ssh` off competition infrastructure (**R23**—only screenshots and passwords may leave the range).

1. **Tier 1 — Off-Host Vault on `jumpbox` (`~/tcdc-vault`):**
   - **Linux:** Always **PULL from `jumpbox` outward** (`scp` / `10-jumpbox-pull-backups.sh`). Never store jumpbox passwords or jumpbox SSH private keys on DMZ servers.
   - **Windows (`ad`, `mqtt`):** Enable **Share folder → `~/tcdc-vault`** in your Remmina RDP profiles (`https://10.99.X.2:3007`–`3008`), then run `10-windows-dual-backup.ps1 -JumpboxShare '\\tsclient\tcdc-vault'`.
   - **OPNsense:** Download XML backup directly to `~/tcdc-vault/opnsense/` via jumpbox Chromium (`https://10.99.X.2:3001`).
2. **Tier 2 — Fast Local Copy on Each Box:**
   - Keep `/root/tcdc-bak` (locked with `chattr +i -R /root/tcdc-bak`) and `C:\TCDC_Backup` (`icacls` locked) for 10-second restores of defaced web pages, modified zones, or altered `mosquitto.conf`.
3. **Tier 3 — Store Snapshots & Reverts (`https://dash.playtcdc.org/team/store`):**
   - Save currency for hypervisor snapshots after first-hour hardening and emergency reverts if `ad` or `opnsense` gets bricked.

```bash
# On jumpbox (Minutes 0–5): initialize vault and pull Linux backups (ipcam first!)
mkdir -p -m 700 ~/tcdc-vault/{opnsense,ipcam,ns1,ftp-archive,ssh-workstation,artifactorium,ad,mqtt}
bash 10-jumpbox-pull-backups.sh --team X --user washington
```

---

## 8. Phase 0: Universal Linux First-5-Minutes Baseline

Run on **all 5 Ubuntu 26.04 servers** (`ipcam`, `ns1`, `ftp-archive`, `ssh-workstation`, `artifactorium`):

```bash
sudo -i
mkdir -p -m 700 /root/tcdc-bak
cp -a /etc/passwd /etc/shadow /etc/group /etc/sudoers /etc/sudoers.d /etc/ssh /root/tcdc-bak/
ss -H -lntup > /root/tcdc-bak/listeners-init.txt
getent group sudo adm > /root/tcdc-bak/priv-groups.txt
awk -F: '$3 == 0 {print $1}' /etc/passwd          # MUST print ONLY root

# Run wizzbizz read-only baseline & Wazuh verification
bash /root/wizzbizz/00-system-audit.sh
bash /root/wizzbizz/02-persistence-audit.sh
bash /root/wizzbizz/06-drift-compare.sh
bash /root/wizzbizz/07-wazuh-verify.sh --manager-ip 10.100.0.11

# Audit non-system users and sudoers
awk -F: '$3 >= 1000 && $3 < 60000 {print $1, $3, $7}' /etc/passwd
grep -rnEv '^[[:space:]]*(#|$)' /etc/sudoers /etc/sudoers.d/
```

### Universal Linux Safe Password Rotation (Skip `blackteam` & `whiteteam`)

```bash
# 1. Rotate root manually
passwd root

# 2. Preview then rotate the 15 museum accounts with your wizzbizz script (sync dashboard immediately!)
bash /root/wizzbizz/08-password-rotation.sh \
  washington kennedy teddy lincoln ross \
  streep franklin parks armstrong hamilton mlk tubman manziel deniro bush

bash /root/wizzbizz/08-password-rotation.sh --apply \
  washington kennedy teddy lincoln ross \
  streep franklin parks armstrong hamilton mlk tubman manziel deniro bush
```

---

## 9. Playbook 1: `opnsense` & `jumpbox` (Perimeter & Management)

- **`opnsense`:** `10.(100+X).40.1` (Mgmt) / `100.64.0.X` (WAN) — OPNsense 26.7 — *Unscored*
- **`jumpbox`:** `10.(100+X).40.22` / `10.99.X.2` — *Unscored*

### Step-by-Step Hardening (Minutes 0–20)
1. **Download Clean XML Backup:** Open `https://10.(100+X).40.1` in jumpbox Chromium → **System → Configuration → Backups → Download configuration** → save to `~/tcdc-vault/opnsense/`.
2. **Rotate Credentials:** **System → Access → Users** → change `root`/admin password; remove any unauthorized local users (never touch `blackteam`/`whiteteam`).
3. **Lock Down Admin Interfaces:** **System → Settings → Administration** → bind Web GUI Listen Interfaces and SSH Listen Interfaces strictly to **Management** (`10.(100+X).40.0/24`), never WAN.
4. **Audit NAT & WAN Rules:** Inspect **Firewall → NAT → Port Forward** and **Firewall → Rules → WAN**. Remove rogue forwards or broad allows into Internal (`.20.0/24`), Users (`.30.0/24`), or Management (`.40.0/24`).
5. **Keep Jumpbox Closed to WAN:** Do **not** open inbound WAN rules to `jumpbox` (default **R6** rules protect it from rival teams).

### R18-Compliant OPNsense Inter-Subnet Segmentation Matrix

| Source Interface | Destination | Allow Rules | Block Action |
| :--- | :--- | :--- | :--- |
| **DMZ** (`.10.0/24`) | Internal (`.20.0/24`), Users (`.30.0/24`), Mgmt (`.40.0/24`) | DNS (`53`) to `ad` only if DMZ resolves via AD; LDAP/Kerberos only if domain-joined (verify first). | **Block all other DMZ → Internal/Users/Mgmt.** |
| **Users** (`.30.0/24`) | Internal (`.20.0/24`), Mgmt (`.40.0/24`) | AD ports from `mqtt` (`.30.49`) → `ad` (`.20.88`): TCP/UDP `53, 88, 389, 445, 464`; TCP `135, 636, 49152–65535`. | **Block RDP (`3389`) / WinRM (`5985–5986`) to `ad`; block all to Mgmt.** |
| **Mgmt** (`.40.0/24`) | All Internal Subnets | SSH (`22`), RDP (`3389`), WinRM, HTTPS (`443`), and scored service ports. | **Allow** outbound from Mgmt to internal subnets. |
| **WAN Outbound** | External | Keep outbound open (**R18** forbids default-deny outbound; preserve `10.100.0.11:1514` for Wazuh). | Surgical C2 blocks only: **1 exact destination IP + 1 exact port**. |

### Jumpbox & OPNsense Monitoring Commands

```bash
# On jumpbox: verify expected Chromium (3001-3006) & Remmina (3007-3008) listeners and active users
ss -H -lntup
who && w

# Keep OPNsense UI "Firewall -> Log Files -> Live View" open in Chromium tab 1 to spot C2 callbacks
```

---

## 10. Playbook 2: `ns1` — DNS (Ubuntu Server 26.04 LTS)

- **IP:** `10.(100+X).10.53` (DMZ) — **Scored** (UDP/TCP `53`)

### Step 1: Identify Daemon, Back Up Zones & Baseline Live Resolution

```bash
ss -H -lntup | grep ':53 '
systemctl list-units --type=service --state=running | grep -Ei 'bind|named|dns|unbound|coredns'

cp -a /etc/bind /root/tcdc-bak/bind 2>/dev/null || true
cp -a /var/cache/bind /root/tcdc-bak/var-bind 2>/dev/null || true
cp -a /etc/dnsmasq* /etc/unbound /etc/coredns /root/tcdc-bak/ 2>/dev/null || true

# Baseline records (replace X with your Team ID)
grep -rn 'zone ' /etc/bind/ 2>/dev/null
dig @127.0.0.1 ns1.teamX.playtcdc.org A +short
dig @127.0.0.1 artifactorium.teamX.playtcdc.org A +short
dig @127.0.0.1 ftp-archive.teamX.playtcdc.org A +short
dig @127.0.0.1 teamX.playtcdc.org SOA +short
```

### Step 2: Observe Scorer & Harden BIND9

```bash
# Watch live DNS queries for 2 minutes before restricting recursion
rndc querylog on 2>/dev/null && journalctl -u named -u bind9 -f --no-pager

# Review /etc/bind/named.conf.options and apply safe hardening:
#   version "not disclosed";
#   allow-transfer { none; };
#   allow-update { none; };
#   (Only add "allow-recursion { localhost; 10.(100+X).0.0/16; };" if scorer does NOT query external names via ns1)

# Validate config & zone files BEFORE reloading
named-checkconf
for z in /etc/bind/zones/db.* /etc/bind/db.*; do
    [ -f "$z" ] && echo "=== $z ===" && head -n 40 "$z"
done
systemctl reload named || systemctl reload bind9
systemctl is-active named || systemctl is-active bind9
```

### Step 3: Host Firewall (UFW) & Rapid Restore

```bash
ufw status numbered
ufw allow 53/udp comment 'TCDC Scored DNS UDP'
ufw allow 53/tcp comment 'TCDC Scored DNS TCP'
ufw allow from 10.(100+X).40.0/24 to any port 22 proto tcp comment 'TCDC Mgmt SSH'
ufw default allow outgoing
ufw status verbose

# Lock clean backup immutable & fast restore if tampered:
chattr +i -R /root/tcdc-bak/bind 2>/dev/null || true
# Diff/Restore:
# diff -ru /root/tcdc-bak/bind /etc/bind
# cp -a /root/tcdc-bak/bind/. /etc/bind/ && named-checkconf && systemctl reload named
```

---

## 11. Playbook 3: `ftp-archive` — FTP (Ubuntu Server 26.04 LTS)

- **IP:** `10.(100+X).10.21` (DMZ) — **Scored** (TCP `21` + Passive Data Ports)

### Step 1: Identify Daemon, Back Up Configs & Archive Data, Observe Scorer

```bash
ss -H -lntup | grep ':21 '
dpkg -V vsftpd 2>/dev/null || dpkg -V proftpd-core 2>/dev/null || true

cp -a /etc/vsftpd* /etc/proftpd* /etc/ftpusers /root/tcdc-bak/ 2>/dev/null || true
grep -Ei 'local_root|anon_root|DefaultRoot' /etc/vsftpd.conf /etc/proftpd/proftpd.conf 2>/dev/null
cp -a /srv/ftp /root/tcdc-bak/srv-ftp 2>/dev/null || true
cp -a /var/ftp /root/tcdc-bak/var-ftp 2>/dev/null || true

# Watch live scorer behavior for 2 minutes (note anon vs. user login, PASV, uploads vs. read-only)
tail -f /var/log/vsftpd.log /var/log/xferlog /var/log/auth.log 2>/dev/null
```

### Step 2: Harden `vsftpd` Safely

```bash
# Inspect active config directives
grep -Ev '^[[:space:]]*(#|$)' /etc/vsftpd.conf

# Recommended safe directives in /etc/vsftpd.conf (adjust anonymous_enable per grace-period logs):
#   anonymous_enable=NO          # Keep YES if scorer uses anonymous; set anon_upload_enable=NO
#   local_enable=YES
#   write_enable=YES             # Set NO only if scorer never uploads
#   chroot_local_user=YES
#   allow_writeable_chroot=YES
#   pasv_enable=YES
#   pasv_min_port=40000
#   pasv_max_port=40100
#   xferlog_enable=YES
#   log_ftp_protocol=YES

# Block root from FTP login (never delete OS accounts!)
grep -qx 'root' /etc/ftpusers || echo 'root' >> /etc/ftpusers

# Restart and test passive listing locally
systemctl restart vsftpd
systemctl status vsftpd --no-pager
curl -v --ftp-pasv ftp://USER:PASS@127.0.0.1/
```

### Step 3: UFW (Include Passive Ports!) & File Integrity

```bash
# CRITICAL: Forgetting the passive port range breaks FTP scoring!
ufw allow 21/tcp comment 'TCDC Scored FTP Control'
ufw allow 40000:40100/tcp comment 'TCDC Scored FTP Passive Data'
ufw allow from 10.(100+X).40.0/24 to any port 22 proto tcp comment 'TCDC Mgmt SSH'
ufw status numbered

# Hash clean archive files
find /srv/ftp -type f -exec sha256sum {} + > /root/tcdc-bak/ftp-files.sha256 2>/dev/null || true
# Verify later: sha256sum -c /root/tcdc-bak/ftp-files.sha256 | grep -v ': OK$'
```

---

## 12. Playbook 4: `artifactorium` & `ipcam` — HTTP (Ubuntu Server 26.04 LTS)

- **`artifactorium`:** `10.(100+X).10.80` (DMZ — HTTP on-prem) — **Scored**
- **`ipcam`:** `10.150.0.X` (Public Cloud `10.150.0.0/24` — HTTP IP Cam SaaS) — **Scored**
- **CRITICAL WARNING:** `ipcam` sits **outside OPNsense**. Harden `ipcam` first!

### Step 1: Stack Discovery, Webroot Backup & Database Dump

```bash
ss -H -lntup
ps -eo pid,user,args | grep -Ei 'nginx|apache|httpd|php|python|gunicorn|uvicorn|node|docker|motion|mediamtx|rtsp|ffmpeg|mysql|mariadb|postgres'
docker ps -a 2>/dev/null || true

cp -a /etc/nginx /etc/apache2 /var/www /opt /srv /root/tcdc-bak/ 2>/dev/null || true
mysqldump --all-databases --single-transaction > /root/tcdc-bak/mysql-all.sql 2>/dev/null || true
su - postgres -c 'pg_dumpall' > /root/tcdc-bak/pg-all.sql 2>/dev/null || true

# Cryptographic baseline of webroot
find /var/www -type f -exec sha256sum {} + > /root/tcdc-bak/webroot.sha256 2>/dev/null || true
```

### Step 2: Watch Checker Endpoints & Hunt Web Shells

```bash
tail -f /var/log/nginx/access.log /var/log/apache2/access.log 2>/dev/null

# Hunt recently modified scripts and RCE patterns
find /var/www /opt -type f \( -name '*.php' -o -name '*.py' -o -name '*.js' -o -name '*.sh' \) -mtime -14 2>/dev/null
grep -rnE '(shell_exec|passthru|system\(|exec\(|base64_decode|eval\(|os\.system|subprocess\.Popen)' /var/www/ 2>/dev/null

# Verify web user has no sudo privileges or write access to app code
sudo -l -U www-data 2>/dev/null || true
find /var/www -writable -user www-data -ls 2>/dev/null | head -n 40
```

### Step 3: Harden Web Server, Local DB & App Credentials

```bash
# Nginx (/etc/nginx/nginx.conf & sites-enabled/*):
#   server_tokens off;
#   autoindex off;
#   location ~ /\. { deny all; }
nginx -t && systemctl reload nginx 2>/dev/null || true

# Apache (/etc/apache2/conf-enabled/security.conf):
#   ServerTokens Prod
#   ServerSignature Off
#   Options -Indexes
apache2ctl configtest && systemctl reload apache2 2>/dev/null || true

# Verify DB binds strictly to 127.0.0.1 (check bind-address in /etc/mysql/mariadb.conf.d/50-server.cnf)
ss -H -lntup | grep -E ':(3306|5432|6379|27017) '

# Verify HTTP 200 after every change
curl -i -s http://127.0.0.1/ | head -n 25
```

### Step 4: Host Firewall (UFW) — `artifactorium` vs. `ipcam`

```bash
# On artifactorium (inside OPNsense DMZ):
ufw allow 80/tcp comment 'TCDC Scored HTTP'
# Add 443/tcp or app port if shown in ss -H -lntup
ufw allow from 10.(100+X).40.0/24 to any port 22 proto tcp comment 'TCDC Mgmt SSH'
ufw status numbered

# On ipcam (Public Cloud 10.150.0.X — OUTSIDE OPNsense):
who && ss -H -tnp sport = :22    # Confirm your NAT'd WAN source IP (usually 100.64.0.X)
ufw allow 80/tcp comment 'TCDC Scored IPCam HTTP'
# Add any confirmed camera stream port (e.g., 443/8080/8554) from Any.
# R18 WARNING: Do NOT block specific outside IPs/ranges on inbound rules!
# Rotate IP Cam web UI admin/service passwords & immediately sync at dash.playtcdc.org/team/passwords!
```

---

## 13. Playbook 5: `ssh-workstation` — SSH (Ubuntu Server 26.04 LTS)

- **IP:** `10.(100+X).10.22` (DMZ) — **Scored** (TCP `22` or configured `sshd` port)

### Step 1: Run Full `wizzbizz` Audit Suite

```bash
# All-in-one SSH audit + topology + Wazuh TCP 1514 check (replace X with Team ID)
sudo bash /root/wizzbizz/TCDC-SSH-Ubuntu-Audit.sh --team X --check-wazuh 10.100.0.11

# Modular audit & compliance baseline
sudo bash /root/wizzbizz/00-system-audit.sh
sudo bash /root/wizzbizz/01-port-audit.sh
sudo bash /root/wizzbizz/02-persistence-audit.sh
sudo bash /root/wizzbizz/04-compliance-audit.sh
sudo bash /root/wizzbizz/06-drift-compare.sh
sudo bash /root/wizzbizz/07-wazuh-verify.sh --manager-ip 10.100.0.11
```

### Step 2: Observe Scorer & Hunt SSH / PAM Persistence

```bash
tail -f /var/log/auth.log

# Inspect effective sshd config for backdoor overrides
sshd -T | grep -Ei 'port|permitrootlogin|passwordauthentication|authorizedkeyscommand|forcecommand|allowusers|denyusers|permituserenvironment|maxauthtries'

# Check PAM for pam_exec.so / pam_permit.so backdoors
grep -rnEv '^[[:space:]]*(#|$)' /etc/pam.d/sshd /etc/pam.d/common-auth

# Inspect authorized_keys (NEVER wipe blackteam, whiteteam, or scorer keys!)
find /home /root -maxdepth 3 -name 'authorized_keys*' -ls -exec cat {} \; 2>/dev/null
ls -la /etc/ld.so.preload 2>/dev/null
```

### Step 3: Apply First-Match-Wins `sshd` Drop-In & UFW Rule

> **Keep `PasswordAuthentication yes`** unless you have 100% proof the scorer uses key-only auth. Always test a **new** SSH session from your jumpbox before closing your active session.

```bash
# Preview then apply /etc/ssh/sshd_config.d/00-identity-hardening.conf
sudo bash /root/wizzbizz/05-identity-plan.sh
sudo bash /root/wizzbizz/05-identity-plan.sh --apply

# Append tunneling/forwarding blocks to stop SSH pivoting
cat <<'EOF' >> /etc/ssh/sshd_config.d/00-identity-hardening.conf
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no
ClientAliveInterval 300
ClientAliveCountMax 2
EOF

# Validate, verify effective config, reload, and test a SECOND SSH session before exiting!
sshd -t && sshd -T | grep -E '^(permitrootlogin|permitemptypasswords|maxauthtries|allowtcpforwarding) '
systemctl reload ssh || systemctl reload sshd

# Preview then apply broad UFW allow rule for confirmed SSH port
sudo bash /root/wizzbizz/03-protect-scored-service.sh 22
sudo bash /root/wizzbizz/03-protect-scored-service.sh 22 --apply
ufw status numbered
```

---

## 14. Playbook 6: `ad` — Active Directory (Windows Server 2025)

- **IP:** `10.(100+X).20.88` (Internal Servers) — **Scored** (LDAP/LDAPS `389/636`, Kerberos `88`, DNS `53`, AD Auth)

### Step 1: Private Backup, AD Health & `wizzbizz` Baseline (Elevated PowerShell)

```powershell
cd C:\Tools\wizzbizz
.\00-system-audit.ps1
.\02-persistence-audit.ps1
.\06-drift-compare.ps1
.\07-wazuh-verify.ps1 -ManagerIP 10.100.0.11

New-Item -ItemType Directory -Path C:\TCDC_Backup\ad -Force | Out-Null
icacls C:\TCDC_Backup\ad /inheritance:r /grant:r "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F"
netsh advfirewall export C:\TCDC_Backup\ad\fw-before.wfw
dcdiag /q > C:\TCDC_Backup\ad\dcdiag.txt
Get-ADDomainController -Filter * | Select-Object HostName, IPv4Address, Site, OperationMasterRoles
Get-ADUser -Filter * -Properties MemberOf,AdminCount,DoesNotRequirePreAuth,ServicePrincipalName,PasswordLastSet |
    Export-Csv C:\TCDC_Backup\ad\ad-users-before.csv -NoTypeInformation
```

### Step 2: Audit Privileged Groups & Rotate Domain Passwords

> **Note:** Do not use `09-password-rotation.ps1` on `ad` (it uses `Set-LocalUser`). Use `Set-ADAccountPassword` below and immediately sync `https://dash.playtcdc.org/team/passwords`.

```powershell
$privGroups = @('Domain Admins','Enterprise Admins','Schema Admins','Administrators',
                'Account Operators','Backup Operators','DnsAdmins','Server Operators','Remote Desktop Users')
foreach ($g in $privGroups) {
    Write-Host "`n=== $g ===" -ForegroundColor Cyan
    Get-ADGroupMember -Identity $g -ErrorAction SilentlyContinue | Select-Object SamAccountName, ObjectClass
}

# Remove unauthorized members (NEVER touch blackteam, whiteteam, or delete listed museum users!)
# Remove-ADGroupMember -Identity 'Domain Admins' -Members 'rogue_user' -Confirm:$false

# Rotate museum AD accounts (sync dashboard immediately!)
$adminPw = Read-Host -AsSecureString 'Enter new Museum Admin AD password'
$empPw   = Read-Host -AsSecureString 'Enter new Museum Employee AD password'
foreach ($u in @('washington','kennedy','teddy','lincoln','ross')) {
    if (Get-ADUser -Filter "SamAccountName -eq '$u'") { Set-ADAccountPassword $u -Reset -NewPassword $adminPw }
}
foreach ($u in @('streep','franklin','parks','armstrong','hamilton','mlk','tubman','manziel','deniro','bush')) {
    if (Get-ADUser -Filter "SamAccountName -eq '$u'") { Set-ADAccountPassword $u -Reset -NewPassword $empPw }
}
```

### Step 3: Close Classic AD Attack Paths

```powershell
# 1. Hunt AS-REP Roastable accounts
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} | Select-Object SamAccountName, Enabled
# Fix (if not required by legacy scored service): Set-ADAccountControl -Identity <user> -DoesNotRequirePreAuth $false

# 2. Hunt Kerberoastable SPN accounts & Unconstrained Delegation
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName | Select-Object SamAccountName, ServicePrincipalName
Get-ADComputer -Filter {TrustedForDelegation -eq $true} | Select-Object Name, DNSHostName

# 3. Inspect GPOs and SYSVOL for malicious scripts or cPassword XMLs
Get-GPO -All | Select-Object DisplayName, CreationTime, ModificationTime
Get-ChildItem -Path "C:\Windows\SYSVOL" -Recurse -Include *.ps1,*.bat,*.cmd,*.vbs,Groups.xml -ErrorAction SilentlyContinue |
    Select-Object FullName, LastWriteTime

# 4. Disable SMBv1, enforce SMB signing, disable LLMNR, stop Print Spooler
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast -PropertyType DWord -Value 0 -Force | Out-Null
Stop-Service Spooler -Force -ErrorAction SilentlyContinue
Set-Service Spooler -StartupType Disabled -ErrorAction SilentlyContinue

# 5. Enable PowerShell 4104 logging, audit Defender & active sessions
$sbKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
New-Item -Path $sbKey -Force | Out-Null
New-ItemProperty -Path $sbKey -Name EnableScriptBlockLogging -PropertyType DWord -Value 1 -Force | Out-Null
Get-MpPreference | Select-Object DisableRealtimeMonitoring, ExclusionPath, ExclusionProcess, ExclusionExtension
quser

# 6. Verify Firewall profiles & core AD services (do NOT enable aggressive account lockout!)
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
Get-Service NTDS, DNS, Kdc, Netlogon, ADWS | Format-Table Name, Status, StartType -AutoSize
```

---

## 15. Playbook 7: `mqtt` — Mosquitto (Windows 11 Pro)

- **IP:** `10.(100+X).30.49` (Users / Workstations) — **Scored** (Mosquitto MQTT, typically TCP `1883` and/or TLS `8883`)

### Step 1: Audit, Config Inspection & Functional Check (Elevated PowerShell)

```powershell
cd C:\Tools\wizzbizz

# 1. Full read-only audit + topology check + Wazuh TCP 1514 check (replace X with Team ID)
.\TCDC-MQTT-Windows-Hardening.ps1 -TeamNumber X -CheckWazuh -WazuhManagerIP 10.100.0.11

# 2. Modular port, persistence, compliance, drift, and Mosquitto checks
.\01-port-audit.ps1
.\02-persistence-audit.ps1
.\04-compliance-audit.ps1
.\06-drift-compare.ps1
.\08-mosquitto-functional-check.ps1 -ProbePort 1883 -FunctionalTest

# 3. Inspect active mosquitto.conf directives (do NOT flip allow_anonymous without confirming scorer auth!)
$mosqDir = "C:\Program Files\mosquitto"
Get-Content "$mosqDir\mosquitto.conf" | Where-Object { $_ -notmatch '^\s*(#|$)' }

# 4. Manual live MQTT pub/sub sanity test (add -u USER -P PASS if auth is enabled)
& "$mosqDir\mosquitto_sub.exe" -h 127.0.0.1 -p 1883 -t "#" -C 5 -v
& "$mosqDir\mosquitto_pub.exe" -h 127.0.0.1 -p 1883 -t "museum/healthcheck" -m "ok"
```

### Step 2: Apply Verified Hardening, Auto-Restart & Password Rotation

```powershell
# 1. Apply TCDC-aware hardening with confirmed listening port(s) (e.g., 1883 or 1883,8883)
.\TCDC-MQTT-Windows-Hardening.ps1 -TeamNumber X -ApplyHardening -MqttPorts 1883

# 2. Auto-restart Mosquitto in 5 seconds if Red Team kills mosquitto.exe
sc.exe failure mosquitto reset= 60 actions= restart/5000/restart/5000/restart/5000

# 3. Lock down NTFS permissions on Mosquitto install folder
icacls "C:\Program Files\mosquitto" /inheritance:r /grant:r "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX"

# 4. Preview then rotate local museum Windows accounts (skip blackteam/whiteteam; sync dashboard immediately!)
.\09-password-rotation.ps1 -Account washington,kennedy,teddy,lincoln,ross,streep,franklin,parks,armstrong,hamilton,mlk,tubman,manziel,deniro,bush
.\09-password-rotation.ps1 -Account washington,kennedy,teddy,lincoln,ross,streep,franklin,parks,armstrong,hamilton,mlk,tubman,manziel,deniro,bush -Apply

# 5. Re-verify compliance, functional check, and read-only Wazuh status (skip lockout!)
.\04-compliance-audit.ps1
.\07-wazuh-verify.ps1 -ManagerIP 10.100.0.11
.\08-mosquitto-functional-check.ps1 -ProbePort 1883 -FunctionalTest
```

---

## 16. Wazuh Strategy, Lightweight Monitoring & Drift Checks

### Why NOT to Install a Second Wazuh Agent
- Every competition host ships with a **Black Team-managed, pre-enrolled Wazuh agent** sending telemetry over outbound TCP `1514` to `wazuh.blackteam.playtcdc.org` (`10.100.0.11`).
- Standard Wazuh installers overwrite `/var/ossec` or `C:\Program Files (x86)\ossec-agent` and violate **R7** & **R15**.
- **Strategy:** Verify Black Team's agent read-only with `07-wazuh-verify`, leave it strictly untouched, and run zero-conflict native monitoring instead.

### Zero-Conflict Central Linux Syslog (`rsyslog`)

```bash
# On jumpbox (10.(100+X).40.22): collect TCP 514 logs from all 5 Ubuntu servers
cat <<'EOF' | sudo tee /etc/rsyslog.d/10-tcdc-collector.conf >/dev/null
module(load="imtcp")
input(type="imtcp" port="514")
$template RemoteLogs,"/var/log/tcdc-remote/%HOSTNAME%.log"
*.* ?RemoteLogs
& stop
EOF
sudo mkdir -p -m 700 /var/log/tcdc-remote && sudo systemctl restart rsyslog

# On each Linux server (ns1, ftp-archive, ssh-workstation, artifactorium, ipcam):
echo "*.* @@10.(100+X).40.22:514" | sudo tee /etc/rsyslog.d/90-tcdc-forward.conf >/dev/null
sudo systemctl restart rsyslog

# Live auth/sudo watch from jumpbox:
sudo tail -f /var/log/tcdc-remote/*.log | grep -Ei 'Accepted|Failed|sudo|useradd|crontab|sshd'
```

### Windows Live Alert Dashboard & 20-Minute Drift Cadence

```powershell
# On mqtt (Elevated PowerShell — stop with Ctrl+C before Lunch/5 PM hands-off!):
.\10-mqtt-alert-dashboard.ps1 -MqttPorts 1883 -IntervalSeconds 15 -OpenHtml

# Windows 20-min drift diff & quick event hunt:
.\06-drift-compare.ps1
.\06-drift-compare.ps1 -CompareOld C:\TCDC_Backup\drift\INITIAL -CompareNew C:\TCDC_Backup\drift\LATEST
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045; StartTime=(Get-Date).AddMinutes(-30)} -ErrorAction SilentlyContinue | Format-List TimeCreated, Message
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104; StartTime=(Get-Date).AddMinutes(-30)} -MaxEvents 25 -ErrorAction SilentlyContinue | Format-List TimeCreated, Message
```

```bash
# Linux 20-min drift diff:
sudo bash /root/wizzbizz/06-drift-compare.sh
sudo bash /root/wizzbizz/06-drift-compare.sh --compare /root/tcdc-ssh-backups/drift/run.INITIAL /root/tcdc-ssh-backups/drift/run.LATEST
```

---

## 17. Emergency Triage & Recovery One-Liners

### Linux Emergency Triage

```bash
ss -H -tnp state established                                          # Active remote TCP connections
ps -eo pid,ppid,user,lstart,args --forest                             # Process tree (spot reverse shells)
sha256sum -c /root/tcdc-bak/webroot.sha256 2>/dev/null | grep -v OK$  # Detect defaced web files
diff -ru /root/tcdc-bak/bind /etc/bind 2>/dev/null                    # Detect tampered DNS zones
ufw status numbered                                                   # Spot rogue DENY rules (remove: ufw delete N)
systemctl restart named vsftpd nginx apache2 ssh 2>/dev/null          # Restart specific downed service
```

### Windows Emergency Triage

```powershell
quser                                                                 # Active RDP / interactive sessions
Get-NetTCPConnection -State Established | Select-Object LocalPort,RemoteAddress,RemotePort,OwningProcess
Get-Service mosquitto,NTDS,DNS,Kdc,Netlogon -ErrorAction SilentlyContinue | Format-Table Name,Status,StartType
Restart-Service mosquitto                                             # Immediate MQTT service restart
Get-MpPreference | Select-Object DisableRealtimeMonitoring,ExclusionPath,ExclusionProcess
# Firewall rollback (only if needed): netsh advfirewall import C:\TCDC_Backup\ad\fw-before.wfw
```

---

## 18. Game-Day Tracking Templates (Passwords, Store, Injects, IR)

> Keep live passwords and screenshots **out of your public GitHub repo**—track them locally in team notes per **R23**.

### Password Rotation & Dashboard Sync Log

| Box / Service | Account(s) | Vault Ref | Rotated (CT) | Synced in `dash.playtcdc.org`? | Scoreboard Green (90s)? |
| :--- | :--- | :--- | :--- | :---: | :---: |
| `opnsense` | `root` | | | N/A | N/A |
| `ipcam` | Museum OS / App | | | [ ] | [ ] |
| `ns1` | Museum OS | | | [ ] | [ ] |
| `ftp-archive` | Museum OS / FTP | | | [ ] | [ ] |
| `artifactorium` | Museum OS / Web / DB | | | [ ] | [ ] |
| `ssh-workstation` | Museum OS | | | [ ] | [ ] |
| `ad` | Domain Admin / Museum AD | | | [ ] | [ ] |
| `mqtt` | Local OS / Mosquitto | | | [ ] | [ ] |
