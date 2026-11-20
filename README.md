# WizzBizz TCDC Defense Scripts

Small, independent scripts for auditing and protecting the TCDC MQTT and SSH
hosts. Run the modules separately and review each report before applying a
change.

## Windows 11 / MQTT

Run from elevated PowerShell:

```powershell
.\TCDC-MQTT-01-Port-Audit.ps1
.\TCDC-MQTT-02-Persistence-Audit.ps1
.\TCDC-MQTT-03-Protect.ps1 -Port <confirmed-mqtt-port>
.\TCDC-MQTT-03-Protect.ps1 -Port <confirmed-mqtt-port> -Apply
```

## Ubuntu / SSH

```bash
sudo bash TCDC-SSH-01-Port-Audit.sh
sudo bash TCDC-SSH-02-Persistence-Audit.sh
sudo bash TCDC-SSH-03-Protect.sh <confirmed-ssh-port>
sudo bash TCDC-SSH-03-Protect.sh <confirmed-ssh-port> --apply
```

The protection scripts verify that the requested port belongs to Mosquitto or
`sshd` before adding a firewall allow.

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


