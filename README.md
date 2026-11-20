# WizzBizz TCDC Defense Scripts

Small, independent scripts for auditing and protecting the TCDC MQTT and SSH
hosts. Run the modules separately and review each report before applying a
change.

## Windows 11 / MQTT

Run from elevated PowerShell:

```powershell
.\TCDC-MQTT-00-System-Audit.ps1
.\TCDC-MQTT-01-Port-Audit.ps1
.\TCDC-MQTT-02-Persistence-Audit.ps1
.\TCDC-MQTT-03-Protect.ps1 -Port <confirmed-mqtt-port>
.\TCDC-MQTT-03-Protect.ps1 -Port <confirmed-mqtt-port> -Apply
.\TCDC-MQTT-04-Compliance-Audit.ps1
.\TCDC-MQTT-05-Identity-Plan.ps1
.\TCDC-MQTT-06-Baseline-Compare.ps1
```

## Ubuntu / SSH

```bash
sudo bash TCDC-SSH-00-System-Audit.sh
sudo bash TCDC-SSH-01-Port-Audit.sh
sudo bash TCDC-SSH-02-Persistence-Audit.sh
sudo bash TCDC-SSH-03-Protect.sh <confirmed-ssh-port>
sudo bash TCDC-SSH-03-Protect.sh <confirmed-ssh-port> --apply
sudo bash TCDC-SSH-04-Compliance-Audit.sh
sudo bash TCDC-SSH-05-Identity-Plan.sh
sudo bash TCDC-SSH-06-Baseline-Compare.sh
```

The protection scripts verify that the requested port belongs to Mosquitto or
`sshd` before adding a firewall allow.

The `04` scripts report explicit TCDC-safe controls; they are not a claim of
full CIS/STIG compliance. The `05` scripts are plan-only identity changes unless
an operator supplies `-Apply`/`--apply`. The `06` scripts produce state manifests
for repeatable drift comparison:

```powershell
.\TCDC-MQTT-06-Baseline-Compare.ps1
.\TCDC-MQTT-06-Baseline-Compare.ps1 -CompareOld OLD_RUN -CompareNew NEW_RUN
```

```bash
sudo bash TCDC-SSH-06-Baseline-Compare.sh
sudo bash TCDC-SSH-06-Baseline-Compare.sh --compare OLD_RUN NEW_RUN
```

The `00-System-Audit` scripts are the recommended first commands. They capture
host identity, IPv4/IPv6 addresses and prefixes, adapters, MAC addresses, routes,
default gateway, DNS, ARP/neighbors, firewall state, listening and established
sockets with process ownership, users, services, scheduled tasks/timers,
installed software/packages, and persistence metadata. They do not collect
password hashes, private keys, shell history, or environment variables.

## Existing Wazuh Agent Verification

These verifiers do not install, re-enroll, restart, or edit the Black Team
managed agent. They verify service state, DNS, local logs, and outbound TCP 1514.

```powershell
.\TCDC-Wazuh-Verify.ps1 -ManagerIP <confirmed-manager-ip>
.\TCDC-Wazuh-Verify.ps1 -ManagerIP <confirmed-manager-ip> -AllowFirewall
```

```bash
sudo bash TCDC-Wazuh-Verify.sh --manager-ip <confirmed-manager-ip>
sudo bash TCDC-Wazuh-Verify.sh --manager-ip <confirmed-manager-ip> --allow-firewall
```


