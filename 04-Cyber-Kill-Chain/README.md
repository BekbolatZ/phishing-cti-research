# Week 4 — Cyber Kill Chain Analysis of Phishing Infrastructure

## Overview

This assignment analyzes a real-world phishing campaign using the
Lockheed Martin Cyber Kill Chain model and maps the attack stages to
MITRE ATT&CK techniques.

The analyzed case is a USPS-themed phishing campaign associated with
the domain:

`delivery-usps.vip`

The phishing infrastructure was previously investigated using
VirusTotal, Shodan and MISP as part of the previous CTI assignments.

---

# 1. Objectives

The objectives of this assignment are:

- Understand the seven stages of the Cyber Kill Chain.
- Analyze a real-world phishing attack using the Cyber Kill Chain.
- Map relevant attack activities to MITRE ATT&CK techniques.
- Develop SIEM correlation rules for detecting activity at different
  stages of the attack.
- Develop recommendations and defensive measures for each stage.
- Demonstrate how CTI can be used to improve detection and prevention.

---

# 2. Cyber Kill Chain

The Cyber Kill Chain is a model developed by Lockheed Martin for
describing the stages of a cyberattack.

The seven stages are:

1. Reconnaissance
2. Weaponization
3. Delivery
4. Exploitation
5. Installation
6. Command and Control
7. Actions on Objectives

The model helps security teams understand how an attack progresses
and identify opportunities to detect or stop the attacker.

---

# 3. Real-World Attack: USPS Phishing Campaign

The analyzed case is a USPS-themed phishing campaign associated with
the domain:

`delivery-usps.vip`

The domain was selected because it was publicly documented in
research concerning malicious stockpiled domains and provided a real
IOC for the CTI investigation.

During the previous OSINT investigation, VirusTotal showed that the
domain had malicious/phishing detections.

Historical DNS information also associated the domain with several
IP addresses:

- `43.135.155.184`
- `8.209.202.142`
- `47.245.39.108`

These indicators were subsequently investigated using Shodan and
organized in MISP.

---

# 4. Cyber Kill Chain Analysis

## 4.1 Reconnaissance

During reconnaissance, attackers collect information about potential
victims and their infrastructure.

For a phishing campaign, attackers may research:

- Organizations and employees
- Email addresses
- Public websites
- Domain names
- Internet-facing infrastructure

### MITRE ATT&CK Mapping

**T1595 — Active Scanning**

Attackers may scan publicly accessible infrastructure to identify
potential targets and services.

**Evidence level:** Possible / analytical mapping.

---

## 4.2 Weaponization

During weaponization, attackers prepare the infrastructure and
content required for the phishing campaign.

In this scenario, attackers may prepare:

- Phishing domains
- Fake delivery notifications
- Spoofed websites
- Credential harvesting pages

### MITRE ATT&CK Mapping

**T1583 — Acquire Infrastructure**

Attackers may acquire domains or other infrastructure to support
their phishing operation.

**Evidence level:** Supported by the presence of phishing
infrastructure, but the exact acquisition process is not directly
observable.

---

## 4.3 Delivery

Delivery is the stage where the malicious content reaches the victim.

In a phishing campaign, this may occur through:

- Email
- Malicious links
- Fake delivery notifications
- Social engineering messages

The domain `delivery-usps.vip` is particularly relevant to this stage
because it represents phishing infrastructure used in a USPS-themed
campaign.

### MITRE ATT&CK Mapping

**T1566 — Phishing**

Attackers use phishing messages or links to deliver malicious content
to victims.

**Evidence level:** Supported by the phishing campaign context.

---

## 4.4 Exploitation

In a phishing attack, exploitation can occur when the victim interacts
with the malicious content.

For example, a victim may:

- Click a phishing link.
- Open a malicious attachment.
- Enter information into a fake login page.

### MITRE ATT&CK Mapping

**T1204 — User Execution**

The attack depends on the victim interacting with malicious content.

**Evidence level:** Possible / analytical mapping.

---

## 4.5 Installation

Installation represents establishing malicious software or other
persistent access on the victim's system.

For the investigated phishing infrastructure, installation cannot be
directly confirmed using the available public OSINT data.

Possible activity could include:

- Downloading malware
- Installing malicious software
- Installing a malicious browser extension
- Establishing persistence

### MITRE ATT&CK Mapping

No specific installation technique is confirmed for this campaign.

**Evidence level:** Not confirmed.

This distinction is important because the available evidence
primarily concerns phishing infrastructure rather than malware
execution on a victim device.

---

## 4.6 Command and Control

Command and Control describes communication between compromised
systems and attacker-controlled infrastructure.

In a phishing scenario, compromised systems or browsers may
communicate with attacker-controlled domains or servers.

### MITRE ATT&CK Mapping

**T1071 — Application Layer Protocol**

Attackers may use application-layer protocols for communication
between compromised systems and attacker-controlled infrastructure.

**Evidence level:** Possible / analytical mapping.

The available OSINT data does not directly prove C2 communication.

---

## 4.7 Actions on Objectives

The final stage represents the attacker's intended objective.

For a phishing campaign, possible objectives include:

- Credential theft
- Account takeover
- Collection of personal information
- Financial fraud
- Further access to organizational resources

### MITRE ATT&CK Mapping

**T1056 — Input Capture**

Attackers may collect credentials or other information entered by the
victim.

**Evidence level:** Possible / analytical mapping.

The exact final objective of the investigated campaign cannot be fully
confirmed using the available public data.

---

# 5. Attack Flow

The analyzed phishing scenario can be represented as:

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

# 6. MITRE ATT&CK Mapping

| Cyber Kill Chain Stage | MITRE ATT&CK Technique | ID | Evidence |
|---|---|---|---|
| Reconnaissance | Active Scanning | T1595 | Possible |
| Weaponization | Acquire Infrastructure | T1583 | Supported |
| Delivery | Phishing | T1566 | Supported |
| Exploitation | User Execution | T1204 | Possible |
| Installation | No confirmed technique | — | Not confirmed |
| Command and Control | Application Layer Protocol | T1071 | Possible |
| Actions on Objectives | Input Capture | T1056 | Possible |

The mapping should not be interpreted as proof that every listed
technique was used by the specific threat actor.

Techniques marked as "Possible" represent analytical mapping based on
typical phishing behavior.

---
### 6.1 Hunting hypotheses and queries for phishing
 
**Hypothesis A:** users visited a newly registered domain that contains one of our brand keywords (Delivery, Exploitation).
 
```spl
index=proxy
| lookup newly_registered_domains domain AS dest_domain OUTPUT age_days
| where age_days < 30 AND match(dest_domain, "(?i)(<brand1>|<brand2>|login|secure|sso)")
| stats count values(user) as users by dest_domain
```
 
**Hypothesis B:** a click on a link in an email is followed by a login POST to a domain not seen before (credential entry).
 
```spl
index=proxy http_method=POST uri_path IN ("*login*","*signin*","*auth*")
| stats earliest(_time) as first_seen by dest_domain
| where first_seen > relative_time(now(), "-1d")
```
 
**Hypothesis C:** after a login from a new IP, a mailbox rule that forwards or hides messages is created (Installation).
 
```spl
index=o365 Operation IN ("New-InboxRule","Set-InboxRule")
| search Parameters="*ForwardTo*" OR Parameters="*DeleteMessage*" OR Parameters="*MoveToFolder*RSS*"
| table _time UserId ClientIP Parameters
```
 
These are illustrative queries, so adapt field and index names to the logs your lab environment provides.
 
---

# 7. SIEM Correlation Rules

SIEM correlation rules can be used to detect suspicious activity
associated with different stages of the Cyber Kill Chain.

## Reconnaissance

- Alert when a large number of DNS queries are generated for
  previously unseen or suspicious domains.
- Alert when external systems receive scanning or connection attempts
  from IP addresses associated with known malicious infrastructure.

## Weaponization

- Alert when newly registered or suspicious domains are used in
  phishing emails.
- Alert when email attachments contain known malicious hashes or
  suspicious file types.

## Delivery

- Alert when a user clicks a suspicious URL received through email.
- Alert when an email contains a link to a domain with a known
  phishing or malicious reputation.
- Alert when a user accesses `delivery-usps.vip` or related
  suspicious infrastructure.

## Exploitation

- Alert when a user submits credentials to a known or suspected
  phishing domain.
- Alert when a user is redirected from an email link to a suspicious
  login page.

## Installation

- Alert when a device downloads a file immediately after visiting a
  suspicious phishing domain.
- Alert when an unauthorized application or browser extension is
  installed after interaction with a suspicious URL.

## Command and Control

- Alert when a device communicates with a known malicious IP address
  or domain.
- Alert when a device repeatedly communicates with suspicious external
  infrastructure after visiting a phishing domain.

## Actions on Objectives

- Alert when credentials are used from an unusual IP address or
  location after suspected phishing activity.
- Alert when abnormal access to sensitive organizational resources
  occurs after suspected credential theft.
- Alert when large amounts of sensitive data are accessed or
  exfiltrated.

---

# 8. Recommendations and Defensive Measures

## Reconnaissance

### Recommendations

- Monitor threat intelligence feeds for newly discovered phishing
  domains and malicious infrastructure.
- Monitor DNS logs and external reconnaissance activity.
- Use VirusTotal and MISP to enrich and correlate suspicious IOCs.

### Protection

- Minimize publicly exposed services.
- Regularly review the organization's external attack surface.
- Use IDS/IPS and network monitoring to detect scanning activity.

---

## Weaponization

### Recommendations

- Monitor newly registered domains that imitate trusted organizations.
- Maintain updated threat intelligence feeds.
- Share phishing indicators with security teams and trusted CTI
  communities.

### Protection

- Deploy endpoint protection and EDR.
- Use sandboxing to analyze suspicious attachments.
- Configure DNS security and firewalls to block known malicious
  domains and IP addresses.

---

## Delivery

### Recommendations

- Train employees to recognize phishing emails and suspicious links.
- Continuously update email filtering rules using threat intelligence.
- Monitor emails for domains impersonating trusted organizations.

### Protection

- Deploy secure email gateways with anti-phishing capabilities.
- Block known malicious URLs and domains.
- Use URL reputation and sandboxing.
- Implement SPF, DKIM and DMARC.

---

## Exploitation

### Recommendations

- Monitor user interaction with suspicious links and websites.
- Alert when users submit credentials to suspicious domains.
- Conduct regular phishing-awareness training and simulated phishing
  exercises.

### Protection

- Implement Multi-Factor Authentication (MFA).
- Use web filtering to block known phishing websites.
- Deploy IDS/IPS and EDR.
- Restrict risky browser extensions and unnecessary scripts.

---

## Installation

### Recommendations

- Monitor endpoints for files downloaded after visiting suspicious
  websites.
- Monitor installation of unauthorized applications and browser
  extensions.
- Maintain an inventory of approved software.

### Protection

- Use EDR and antivirus solutions.
- Implement application allowlisting where appropriate.
- Restrict users from installing unauthorized software.
- Keep operating systems and applications patched.
- Apply least-privilege access.

---

## Command and Control

### Recommendations

- Monitor network connections to known malicious IP addresses and
  domains.
- Correlate DNS, proxy, firewall and endpoint logs.
- Add confirmed malicious infrastructure to organizational blocklists.

### Protection

- Use DNS filtering.
- Block known malicious IP addresses and domains with firewalls.
- Deploy IDS/IPS and EDR.
- Restrict unnecessary outbound network traffic.

---

## Actions on Objectives

### Recommendations

- Monitor authentication logs for unusual login activity.
- Detect logins from unusual IP addresses or locations.
- Investigate accounts associated with suspected credential theft.

### Protection

- Implement MFA and phishing-resistant authentication such as
  FIDO2/WebAuthn.
- Use least-privilege access and Privileged Access Management (PAM).
- Monitor sensitive account activity using SIEM.
- Reset compromised credentials immediately.
- Implement Data Loss Prevention (DLP).

---

# 9. Overall Defensive Strategy

The phishing campaign should be addressed using multiple layers of
security:

```text
Email Security
      ↓
DNS / Web Filtering
      ↓
Endpoint Protection / EDR
      ↓
MFA / Identity Security
      ↓
SIEM Monitoring
      ↓
Incident Response
```

# 10. Limitations

The investigation is based primarily on publicly available
information and the attack scenario described in the course materials.

Therefore, some stages of the Cyber Kill Chain cannot be directly
confirmed.

In particular:

- Exact reconnaissance activities are not observable.
- The exact weaponization process is unknown.
- Installation was not confirmed.
- Command and Control communication was not directly observed.
- The attacker's final objective cannot be fully confirmed.

Therefore, the analysis clearly separates confirmed information from
possible attacker behavior.

---

# 11. Conclusion

The Cyber Kill Chain provides a high-level model for understanding the
progression of a phishing attack.

The analyzed USPS phishing scenario demonstrates how the seven stages
of the Cyber Kill Chain can be applied to a real-world phishing
campaign.

MITRE ATT&CK provides a more detailed mapping of possible attacker
techniques and behaviors.

By combining the Cyber Kill Chain with MITRE ATT&CK and SIEM
correlation rules, security teams can better understand, detect and
respond to phishing attacks at different stages of the attack
lifecycle.

---

# 12. Sources

- **Lecture 4 — The Cyber Kill Chain**  
  Course lecture materials provided by Astana IT University.

- **Lockheed Martin — Cyber Kill Chain**  
  https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html

- **Lockheed Martin — Gaining the Advantage: Applying Cyber Kill Chain Methodology**  
  https://www.lockheedmartin.com/content/dam/lockheed-martin/rms/documents/cyber/Gaining_the_Advantage_Cyber_Kill_Chain.pdf

- **MITRE ATT&CK — Enterprise Matrix**  
  https://attack.mitre.org/

- **MITRE ATT&CK Navigator**  
  https://mitre-attack.github.io/attack-navigator/
