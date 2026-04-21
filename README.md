# Azuki-Series-Pt-1-Port-of-Entry (WIP)

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




