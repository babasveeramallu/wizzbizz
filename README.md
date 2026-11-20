# WizzBizz Defense Scripts

Independent scripts for the Windows MQTT and Ubuntu SSH hosts. Run each module
separately and review its report before applying a change.

## MQTT

Run from elevated PowerShell:

```powershell
cd mqtt

.\00-System-Audit.ps1
.\01-Port-Audit.ps1
.\02-Persistence-Audit.ps1
.\03-Protect.ps1 -Port <confirmed-mqtt-port>
.\03-Protect.ps1 -Port <confirmed-mqtt-port> -Apply
.\04-Compliance-Audit.ps1
.\05-Identity-Plan.ps1
.\06-Baseline-Compare.ps1
.\07-Wazuh-Verify.ps1 -ManagerIP <confirmed-manager-ip>
.\08-Mosquitto-Check.ps1 -FunctionalTest
.\09-Password-Rotation.ps1 -Account washington,kennedy
```

## SSH

```bash
cd ssh

sudo bash 00-System-Audit.sh
sudo bash 01-Port-Audit.sh
sudo bash 02-Persistence-Audit.sh
sudo bash 03-Protect.sh <confirmed-ssh-port>
sudo bash 03-Protect.sh <confirmed-ssh-port> --apply
sudo bash 04-Compliance-Audit.sh
sudo bash 05-Identity-Plan.sh
sudo bash 06-Baseline-Compare.sh
sudo bash 07-Wazuh-Verify.sh --manager-ip <confirmed-manager-ip>
sudo bash 09-Password-Rotation.sh washington kennedy
```

The `00` modules are detailed read-only inventories. The `04` modules report
explicit controls but do not claim full CIS/STIG compliance. Identity and
protection modules are plan-only unless `-Apply` or `--apply` is supplied.

The `08-Mosquitto-Check` script backs up and audits broker security directives
and tests local TCP readiness. The `09-Password-Rotation` scripts are plan-only
until explicitly applied, exclude protected competition accounts, save a private
credential sheet, and require dashboard synchronization immediately afterward.

## Drift Comparison

```powershell
.\mqtt\06-Baseline-Compare.ps1
.\mqtt\06-Baseline-Compare.ps1 -CompareOld OLD_RUN -CompareNew NEW_RUN
```

```bash
sudo bash ssh/06-Baseline-Compare.sh
sudo bash ssh/06-Baseline-Compare.sh --compare OLD_RUN NEW_RUN
```
