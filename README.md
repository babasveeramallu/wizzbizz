# WizzBizz Defense Scripts

Independent scripts for the Windows MQTT and Ubuntu SSH hosts. Run each module
separately and review its report before applying a change.

## Backup

Run the pull workflow on the jumpbox:

```bash
bash backup/jumpbox-pull-backups.sh --team 3 --user washington
```

Run the Windows workflow elevated on MQTT or AD:

```powershell
.\backup\windows-dual-backup.ps1 -JumpboxShare '\\tsclient\tcdc-vault'
```

The backup workflows keep credentials off managed servers. Linux uses outbound
SSH/SCP initiated by the jumpbox, and Windows can use a Remmina shared folder or
interactive SCP. Only the Remmina-share Windows path verifies the copied hash.

## MQTT

Run from elevated PowerShell:

```powershell
cd mqtt

.\00-system-audit.ps1
.\01-port-audit.ps1
.\02-persistence-audit.ps1
.\03-protect-scored-service.ps1 -Port <confirmed-mqtt-port>
.\03-protect-scored-service.ps1 -Port <confirmed-mqtt-port> -Apply
.\04-compliance-audit.ps1
.\05-identity-plan.ps1
.\06-drift-compare.ps1
.\07-wazuh-verify.ps1 -ManagerIP <confirmed-manager-ip>
.\08-mosquitto-functional-check.ps1 -FunctionalTest
.\09-password-rotation.ps1 -Account washington,kennedy
.\10-mqtt-alert-dashboard.ps1 -MqttPorts <confirmed-mqtt-port> -OpenHtml
```

## SSH

```bash
cd ssh

sudo bash 00-system-audit.sh
sudo bash 01-port-audit.sh
sudo bash 02-persistence-audit.sh
sudo bash 03-protect-scored-service.sh <confirmed-ssh-port>
sudo bash 03-protect-scored-service.sh <confirmed-ssh-port> --apply
sudo bash 04-compliance-audit.sh
sudo bash 05-identity-plan.sh
sudo bash 06-drift-compare.sh
sudo bash 07-wazuh-verify.sh --manager-ip <confirmed-manager-ip>
sudo bash 08-password-rotation.sh washington kennedy
```

The `00` modules are detailed read-only inventories. The `04` modules report
explicit controls but do not claim full CIS/STIG compliance. Identity and
protection modules are plan-only unless `-Apply` or `--apply` is supplied.

The `08-mosquitto-functional-check` script backs up and audits broker security directives
and tests local TCP readiness. The `09-password-rotation` scripts are plan-only
until explicitly applied, exclude protected competition accounts, save a private
credential sheet, and require dashboard synchronization immediately afterward.
The `10-mqtt-alert-dashboard` script is a zero-listener monitor that writes a
private auto-refreshing HTML dashboard and append-only alert log. It never opens
a port or changes firewall, service, account, or Wazuh configuration.

## Drift Comparison

```powershell
.\mqtt\06-drift-compare.ps1
.\mqtt\06-drift-compare.ps1 -CompareOld OLD_RUN -CompareNew NEW_RUN
```

```bash
sudo bash ssh/06-drift-compare.sh
sudo bash ssh/06-drift-compare.sh --compare OLD_RUN NEW_RUN
```
