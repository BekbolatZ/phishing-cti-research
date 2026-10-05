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
```

---

## 5. MITRE ATT&CK Mapping

The main MITRE ATT&CK techniques relevant to the analyzed phishing scenario include:

### T1566 — Phishing

The attacker uses phishing messages or malicious links to deliver the attack to the victim.

### T1204 — User Execution

The attack requires the victim to interact with malicious content, such as opening a link or file.

### T1056 — Input Capture

This technique can describe the collection of credentials or other information entered by the victim.

### T1071 — Application Layer Protocol

Application-layer protocols can be used by compromised systems to communicate with attacker-controlled infrastructure.

### T1583 — Acquire Infrastructure

Attackers may obtain infrastructure such as domains or servers to support their operations.

### T1595 — Active Scanning

Attackers may perform scanning to discover information about target infrastructure.

---

## 6. Cyber Kill Chain vs MITRE ATT&CK

The Cyber Kill Chain and MITRE ATT&CK are complementary frameworks.

### Cyber Kill Chain

Cyber Kill Chain provides a high-level sequence of an attack:

> Reconnaissance → Weaponization → Delivery → Exploitation → Installation → Command and Control → Actions on Objectives

### MITRE ATT&CK

MITRE ATT&CK provides a detailed knowledge base of adversary tactics and techniques.

Therefore:

- Cyber Kill Chain describes the **overall attack progression**.
- MITRE ATT&CK describes **specific attacker techniques and behaviors**.

The two frameworks can be used together to provide both a high-level and technical view of a cyberattack.

---

## 7. Analysis

The phishing infrastructure investigated in previous weeks can be connected to the Cyber Kill Chain.

The domain:

`delivery-usps.vip`

represents infrastructure associated with the phishing campaign and is particularly relevant to the **Delivery** stage.

VirusTotal and Passive DNS provided information about the domain and its historical infrastructure.

The historical IP addresses were then investigated using Shodan.

MISP was subsequently used to organize and process the collected IOCs.

This demonstrates how CTI data can be connected to an attack lifecycle model.

---

## 8. Limitations

Not every Cyber Kill Chain stage can be directly confirmed using publicly available OSINT data.

For example:

- Exact reconnaissance activities may not be observable.
- Weaponization details may not be publicly available.
- Installation cannot be confirmed without evidence of malware execution.
- Command and Control cannot be confirmed without observed C2 communication.
- The final attacker objective may not be directly observable.

Therefore, the analysis distinguishes between **observed evidence** and **possible attack stages**.

The MITRE ATT&CK techniques are used as a mapping framework and should not be interpreted as proof that every technique was used in the specific campaign.

---

## Conclusion

The Cyber Kill Chain provides a high-level model for understanding how cyberattacks progress from reconnaissance to the final objective.

MITRE ATT&CK provides a more detailed description of adversary tactics and techniques.

By combining the two frameworks, the phishing infrastructure investigation can be analyzed from both a high-level attack lifecycle perspective and a technical behavior perspective.

---

## Sources

- Lockheed Martin — Cyber Kill Chain
- MITRE ATT&CK
- Unit 42 — Detecting Malicious Stockpiled Domains
- MISP — Malware Information Sharing Platform
- VirusTotal
- Shodan
