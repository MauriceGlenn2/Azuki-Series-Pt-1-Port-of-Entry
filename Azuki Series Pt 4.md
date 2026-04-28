# INCIDENT BRIEF - Azuki Import/Export - 梓貿易株式会社

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
