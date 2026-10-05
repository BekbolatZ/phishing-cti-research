# Week 4 — Cyber Kill Chain

## Overview

This week focuses on analyzing a real-world cyberattack using the Lockheed Martin Cyber Kill Chain model and mapping the attack stages to relevant MITRE ATT&CK techniques.

The analysis is adapted to the project topic:

**Cyber Threat Intelligence Analysis of Phishing Infrastructure**

## Objectives

- Understand the Cyber Kill Chain model.
- Analyze a real-world phishing attack.
- Identify the different stages of the attack.
- Map attack activities to MITRE ATT&CK techniques.
- Understand the relationship between Cyber Kill Chain and MITRE ATT&CK.

---

## 1. Cyber Kill Chain

The Lockheed Martin Cyber Kill Chain consists of seven stages:

1. Reconnaissance
2. Weaponization
3. Delivery
4. Exploitation
5. Installation
6. Command and Control
7. Actions on Objectives

The model describes how an attacker progresses from initial preparation to achieving the final objective.

---

## 2. Real-World Attack

The analyzed scenario is a phishing campaign targeting users through a malicious phishing website.

The campaign used a phishing domain:

`delivery-usps.vip`

The domain was publicly documented as being associated with a USPS-themed phishing campaign.

The attack can be represented using the Cyber Kill Chain stages.

---

## 3. Kill Chain Analysis

| Kill Chain Stage | Attack Activity | MITRE ATT&CK |
|---|---|---|
| Reconnaissance | Information about the target and organization is collected | T1595 — Active Scanning |
| Weaponization | Phishing infrastructure and malicious content are prepared | T1583 — Acquire Infrastructure |
| Delivery | Victim receives a phishing message or malicious link | T1566 — Phishing |
| Exploitation | Victim interacts with the phishing content | T1204 — User Execution |
| Installation | Malware may be installed if the campaign delivers malicious software | T1204 / execution-related techniques |
| Command and Control | Compromised systems may communicate with attacker infrastructure | T1071 — Application Layer Protocol |
| Actions on Objectives | Attacker attempts to steal credentials or other information | T1056 — Input Capture |

---

## 4. Phishing Attack Flow

The attack can be summarized as:

```text
Reconnaissance
       ↓
Weaponization
       ↓
Delivery
       ↓
Exploitation
       ↓
Installation
       ↓
Command and Control
       ↓
Actions on Objectives
