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

---
<br><br><br>
# Query 3: Persistence — C2 Implant & Archive Extraction

A KQL query was executed against `DeviceFileEvents` targeting `azuki-adminpc` on
November 25, 2025, filtering for `FileCreated` action types where the filename
contains `meterpreter.exe` and the initiating account is not `system`. The goal
was to confirm the extraction of the malicious password-protected archive and
identify the C2 implant dropped onto the CEO's administrative workstation following
the attacker's lateral movement from `azuki-sl`.

---

## Key Findings

The results confirm that `azuki-adminpc` was the affected device. At `4:21:33 AM UTC
on November 25, 2025`, a `FileCreated` event was recorded for `meterpreter.exe` in
`C:\Windows\Temp\cache\`, initiated directly by the 7-Zip extraction command. This
confirms the malicious archive was successfully extracted and the C2 implant was
deployed onto the machine.

<img width="1666" height="427" alt="image" src="https://github.com/user-attachments/assets/9dd315a4-f9c2-4b29-a318-4ab71ea91a03" />

---

## Event Sequence

At `4:21:12 AM UTC`, `curl.exe` contacted `litter.catbox.moe` and downloaded the
password-protected archive `KB5044273-x64.7z` to `C:\Windows\Temp\cache\`. The file
was disguised as a legitimate Microsoft Windows KB update package to blend in with
normal Windows Update activity and avoid raising suspicion during manual log review.

At `4:21:33 AM UTC`, `7z.exe` was invoked to silently extract the archive using a
password and the `-y` flag to suppress all user prompts. The extraction command was:

```
"7z.exe" x C:\Windows\Temp\cache\KB5044273-x64.7z -p******** -oC:\Windows\Temp\cache\ -y
```

The password-protected nature of the archive is significant — encrypted `.7z` files
cannot be inspected by antivirus engines, allowing all three malicious tools to bypass
endpoint detection entirely until the moment of extraction.

Three malicious tools were confirmed extracted to `C:\Windows\Temp\cache\`:

- **`silentlynx.exe`** — a stealthy backdoor and Remote Access Trojan (RAT) designed
to operate silently in the background, providing the attacker with persistent remote
access to the machine even if other tools are discovered and removed.

- **`meterpreter.exe`** — the advanced Metasploit Framework payload. Once executed,
Meterpreter gives the attacker a fully encrypted, in-memory remote shell with
capabilities including file upload and download, privilege escalation, keystroke
logging, webcam access, credential harvesting, and lateral movement pivoting to
other machines on the network.

- **`m.exe`** — Mimikatz, the credential dumping tool previously seen in the
`wupdate.ps1` attack chain on `azuki-sl`. Redeployed here on `azuki-adminpc` for
further credential harvesting from the CEO's machine, where high-value credentials
such as QuickBooks and banking logins were expected to reside.

---

## MITRE ATT&CK

- `T1105` — Ingress Tool Transfer  
- `T1027` — Obfuscated Files or Information *(password-protected archive)*  
- `T1003.001` — OS Credential Dumping: LSASS Memory  
- `T1071.001` — Application Layer Protocol: Web Protocols *(Meterpreter C2)*  
- `T1543` — Create or Modify System Process *(Persistence)*
