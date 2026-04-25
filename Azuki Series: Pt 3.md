# INCIDENT BRIEF - Azuki Import/Export - 梓貿易株式会社

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
azuki-fileserver01
