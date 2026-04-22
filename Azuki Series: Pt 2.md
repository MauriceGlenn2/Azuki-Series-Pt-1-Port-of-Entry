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
