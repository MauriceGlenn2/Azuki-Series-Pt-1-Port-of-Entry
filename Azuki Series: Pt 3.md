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

---
<br><br><br>
# Query 4: Persistence — Named Pipe (C2 Communication Channel)

A KQL query was executed against `DeviceEvents` targeting `azuki-adminpc` on
November 25, 2025, filtering for `NamedPipeEvent` action types initiated by
`meterpreter.exe` where the account is not `system`. The goal was to identify
the named pipe created by the Meterpreter C2 implant as part of its inter-process
communication infrastructure following successful deployment on the CEO's workstation.

---

## Key Findings

The results confirm two `NamedPipeEvent` entries on `azuki-adminpc` on November 25,
2025, both initiated by `meterpreter.exe`. Both events show a `FileOperation` of
`File created` with `NamedPipeEnd` set to `Server` — confirming Meterpreter created
and was actively listening on these pipes for incoming C2 instructions.

The `AdditionalFields` JSON column reveals the pipe names directly:

<img width="1935" height="497" alt="image" src="https://github.com/user-attachments/assets/145ca169-60c5-4fe7-93ef-b227889b4646" />

---

## What Are Named Pipes and Why Do They Matter?

Named pipes are a Windows inter-process communication (IPC) mechanism that allow
two processes to exchange data through a named channel. Legitimate Windows services
use named pipes constantly for normal operations — making them an attractive hiding
place for attacker C2 traffic.

Meterpreter uses named pipes to establish an encrypted communication channel between
the implant on the victim machine and the attacker's C2 server. Because named pipe
traffic can remain local or travel over SMB rather than a dedicated network port,
it is significantly harder to detect than traditional socket-based C2 communication
and can bypass network-level firewall rules.

The prefix `msf-pipe-` is a well-known Metasploit Framework naming pattern — a
strong behavioural indicator that confirms the tool in use is Metasploit's Meterpreter
payload. This naming pattern is commonly flagged in threat intelligence feeds and
endpoint detection rules as a direct indicator of compromise.

---

## MITRE ATT&CK

- `T1071` — Application Layer Protocol *(C2 over named pipe)*  
- `T1543` — Create or Modify System Process *(persistent implant)*  
- `T1059.001` — Command and Scripting Interpreter: PowerShell

---
<br><br><br>
# Query 5: Credential Access — Decoded Account Creation

A KQL query was executed against `DeviceProcessEvents` targeting `azuki-adminpc` on
November 25, 2025, filtering for PowerShell executions containing obfuscated or
encoded input via `-EncodedCommand`, `-enc`, `-en`, `FromBase64String`, or
`encodedcommand`. The goal was to identify malicious commands hidden behind Base64
obfuscation, specifically targeting backdoor account creation activity following the
deployment of the Meterpreter C2 implant.

---

## Key Findings

The highlighted result at `4:51:08 AM UTC on November 25, 2025` reveals a PowerShell
process executing a Base64 encoded command on `azuki-adminpc`:

```
"powershell.exe" -EncodedCommand bgBlAHQAIABsAG8AYwBhAGwAZwByAG8AdQBwACAAQWRtaW5pc3RyYXRvcnMAIAB5AHUAawBpAC4AdABhAG4AYQBrAGEAMgAgAC8AYQBkAGQA
```

<img width="1552" height="497" alt="image" src="https://github.com/user-attachments/assets/1ee9b94b-f985-4f6d-841a-f631f434af4f" />


---

## Decoded Command

When the Base64 payload is decoded the true command is revealed:

```
net localgroup Administrators yuki.tanaka2 /add
```


## What the Attacker is Doing

This command is **Step 2** of a two-step backdoor account creation sequence executed
within seconds of each other:

```
4:51:08 AM  →  net user yuki.tanaka2 B@ckd00r2024! /add
               CREATE the backdoor account with a known password

4:51:23 AM  →  net localgroup Administrators yuki.tanaka2 /add
               ELEVATE the backdoor account to full Administrator
```

By adding `yuki.tanaka2` to the local Administrators group, the attacker ensured
their backdoor account had **full unrestricted access** to `azuki-adminpc` — including
the ability to RDP back into the machine, access all files, modify system settings,
and disable security controls.

The account name `yuki.tanaka2` was deliberately chosen to mimic the legitimate
compromised account `yuki.tanaka`, making it harder for administrators to spot
the rogue account during a cursory review of user accounts on the machine.

---

## Why Base64 Obfuscation Was Used

The attacker encoded both commands in Base64 rather than running them in plaintext
for three key reasons:

**Bypass string matching** — security tools and SIEM rules commonly scan
`ProcessCommandLine` fields for keywords like `net user`, `localgroup`, `/add`,
and `Administrators`. Base64 encoding completely hides these strings from basic
detection rules, meaning the commands would not trigger standard alerts.

**Evade log analysis** — a security analyst manually reviewing logs would see
a long string of random-looking characters rather than an immediately recognisable
account creation command, significantly reducing the chance of detection during
a routine review.

**Blend with legitimate activity** — PowerShell's `-EncodedCommand` flag is used
regularly by legitimate system administrators and automation scripts, meaning its
presence alone does not raise suspicion. The attacker exploited this to hide
malicious commands in plain sight.

This technique is classified under **T1027 — Obfuscated Files or Information**
and is commonly used by advanced threat actors to extend their dwell time on
compromised systems.

---

## MITRE ATT&CK

- `T1136.001` — Create Account: Local Account  
- `T1098` — Account Manipulation  
- `T1027` — Obfuscated Files or Information *(Base64 encoded commands)*  
- `T1059.001` — Command and Scripting Interpreter: PowerShell



