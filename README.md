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

**MITRE ATT&CK:** `T1078` — Valid Accounts  
**MITRE ATT&CK:** `T1021.001` — Remote Services: Remote Desktop Protocol

---

