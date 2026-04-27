# INCIDENT BRIEF - Azuki Import/Export - 梓貿易株式会社 (WIP)

---

## 📋 INCIDENT BRIEF

---

## SITUATION

Five days after the file server breach, threat actors returned with sophisticated tools and techniques. The attacker pivoted from the compromised workstation to the CEO's administrative PC, deploying persistent backdoors and exfiltrating sensitive business data including financial records and password databases.

---
<br><br><br>

# Query 1: Lateral Movement — Compromised Credentials

---

## Key Findings

<img width="843" height="457" alt="image" src="https://github.com/user-attachments/assets/ae059d9b-ef19-428a-ad85-ca8a7e05ae9d" />


The results confirm **two accounts** were used for `RemoteInteractive` logons across
Azuki systems on **November 24, 2025**:

| TimeGenerated [UTC]      | AccountDomain | AccountName | LogonType         | RemoteIP |
|--------------------------|---------------|-------------|-------------------|----------|
| 11/24/2025, 4:11:57 PM   | azuki-adminpc | yuki.tanaka | RemoteInteractive | 10.0.8.4 |
| 11/24/2025, 4:11:57 PM   | azuki-adminpc | yuki.tanaka | RemoteInteractive |          |
| 11/24/2025, 2:53:37 PM   | azuki-adminpc | yuki.tanaka | RemoteInteractive | 10.0.8.9 |
| 11/24/2025, 2:30:05 PM   | azuki-sl      | kenji.sato  | RemoteInteractive | 10.0.8.6 |
| 11/24/2025, 2:30:05 PM   | azuki-sl      | kenji.sato  | RemoteInteractive |          |
| 11/24/2025, 2:17:38 PM   | azuki-adminpc | yuki.tanaka | RemoteInteractive | 10.0.8.9 |
| 11/24/2025, 2:17:38 PM   | azuki-adminpc | yuki.tanaka | RemoteInteractive |          |


---

## What This Reveals

**Account `yuki.tanaka`** — the primary compromised credential used for lateral
movement. This account repeatedly authenticated via RDP to `azuki-adminpc` from
multiple source IPs (`10.0.8.9`, `10.0.8.4`), confirming deliberate movement across
systems rather than a single isolated logon event.

**Multiple source IPs** — the same account authenticating from `10.0.8.9` and `10.0.8.4`
across different timestamps is a classic lateral movement signature. A single legitimate
user would not RDP in from multiple internal IPs within the same session window.

**How the credential was obtained** — during the initial breach (pt1/pt2), the attacker
dumped LSASS memory (`lsass.dmp`) from an Azuki machine and exfiltrated it. The dump
was processed offline using tools such as Mimikatz or pypykatz to extract plaintext
credentials and NTLM hashes. `yuki.tanaka` was among the credentials recovered and
reused directly for RDP lateral movement — no brute force required.

---

## MITRE ATT&CK

- `T1078` — Valid Accounts
- `T1078.003` — Valid Accounts: Local Accounts
- `T1003.001` — OS Credential Dumping: LSASS Memory
- `T1021.001` — Remote Services: Remote Desktop Protocol

---
<br><br><br>
# Query 2: Execution — Payload Hosting Service & Malware Download Command

A KQL query was executed against `DeviceNetworkEvents` targeting `azuki-adminpc`
across a broad timeframe (November 18–25, 2025), filtering for `curl.exe` as the
initiating process with a non-empty `RemoteUrl`. The goal was to identify the external
file hosting service used to stage malware during the attacker's execution phase, and
to surface the exact download command used to retrieve the payload.


---

## Key Findings

<img width="1904" height="350" alt="image" src="https://github.com/user-attachments/assets/fcfc1956-fc3c-440e-996b-10fcf4d7a857" />

---

| TimeGenerated [UTC]      | DeviceName    | RemoteUrl         | RemoteIP       | InitiatingProcess |
|--------------------------|---------------|-------------------|----------------|-------------------|
| 11/25/2025, 4:21:12 AM  | azuki-adminpc | litter.catbox.moe | 108.181.20.36  | curl.exe          |

---

## What This Reveals

**`litter.catbox.moe`** — Catbox is a publicly accessible free file hosting service
commonly abused by attackers to stage malware. It requires no account registration
and files can be uploaded anonymously, making it attractive for staging payloads.

**Infrastructure rotation confirmed** — in pt1/pt2 the attacker used `file.io` as
their hosting service. In pt3 they switched to `litter.catbox.moe`, consistent with
MITRE T1608.001 (Stage Capabilities) — rotating infrastructure to evade network
blocks and threat intelligence feeds that may have flagged `file.io`.

**KB filename masquerade** — the downloaded file was named `KB5044273-x64.7z`,
mimicking a legitimate Microsoft Windows update package. This technique is designed
to blend in with normal Windows Update activity and avoid raising suspicion during
manual log review.

**Hidden staging directory** — the file was saved to `C:\Windows\Temp\cache\`,
a location that blends with legitimate Windows temporary files, making it harder
to detect during routine file system inspection.

**`wupdate.ps1` full attack chain** — the broader investigation of `wupdate.ps1`
revealed the complete attacker playbook executed on `azuki-sl` on November 19, 2025:

---

## MITRE ATT&CK

- `T1608.001` — Stage Capabilities: Upload Malware
- `T1105` — Ingress Tool Transfer
- `T1564.001` — Hide Artifacts: Hidden Files and Directories
- `T1059.001` — Command and Scripting Interpreter: PowerShell
- `T1218.011` — System Binary Proxy Execution: Certutil
