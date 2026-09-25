# Threat Classification

## Overview

Cyber threats can be classified according to their techniques, objectives, targets, and sources.

For this project, the classification focuses on threats related to phishing and malicious Internet infrastructure.

## 1. Social Engineering

Social engineering attacks manipulate people into performing actions that benefit an attacker.

### Examples

- Phishing
- Spear phishing
- Business Email Compromise (BEC)
- Smishing
- Vishing

### Possible Sources

- Individual attackers
- Cybercriminal groups
- Fraud groups
- Organized threat actor groups

## 2. Phishing

Phishing attempts to deceive users through fraudulent communication or websites.

### Examples

- Fake login pages
- Credential harvesting websites
- Fake payment pages
- Fake Microsoft 365 or Google login pages
- Malicious links distributed through email or messaging platforms

### Infrastructure

Phishing campaigns may use:

- Malicious domains
- Compromised websites
- Hosting servers
- IP addresses
- URLs
- Redirectors

### Relevant IOCs

- Domain names
- IP addresses
- URLs
- File hashes
- Email addresses

## 3. Malware

Malware is malicious software designed to perform unauthorized actions.

### Examples

- Trojans
- Ransomware
- Information stealers
- Remote Access Trojans (RATs)
- Botnet malware

### Possible Sources

- Cybercriminal groups
- Malware operators
- Initial Access Brokers
- Advanced Persistent Threat (APT) groups

## 4. Credential Theft

Credential theft involves obtaining usernames, passwords, authentication tokens, or other authentication information without authorization.

### Common Methods

- Phishing
- Credential harvesting websites
- Infostealer malware
- Keylogging
- Fake authentication portals

### Relevant IOCs

- Phishing domains
- URLs
- Malware hashes
- IP addresses
- Email addresses

## 5. Malicious Web Infrastructure

Threat actors may create or compromise Internet infrastructure to support malicious operations.

### Examples

- Malicious domains
- Compromised websites
- Malicious IP addresses
- Suspicious hosting infrastructure
- Redirector infrastructure

This category is especially relevant to the current project because phishing campaigns often depend on external web infrastructure.

# Threat Sources

Threat sources can also be classified according to the actors responsible for generating or using malicious infrastructure.

| Threat Source | Description | Example |
|---|---|---|
| **Cybercriminals** | Individuals or groups motivated primarily by financial gain. | Phishing for banking credentials |
| **Organized Cybercrime Groups** | Structured groups conducting coordinated criminal activities. | Large-scale phishing campaigns |
| **APT Groups** | Long-term, organized threat actors that conduct targeted operations. | Targeted credential theft |
| **Insiders** | Individuals with legitimate access who intentionally or unintentionally cause security incidents. | Unauthorized disclosure of information |
| **Hacktivists** | Actors motivated by political or social objectives. | Website disruption or information disclosure |
| **Botnet Operators** | Actors who operate networks of compromised devices. | Distributed attacks or malicious traffic |
| **Malware Operators** | Actors responsible for distributing or operating malware. | Information-stealing malware |
| **Scammers** | Actors who use deception primarily for fraud or financial gain. | Fake payment or login websites |

# Phishing Threat Chain

A simplified phishing attack chain can be represented as:

```text
Threat Actor
     ↓
Phishing Campaign
     ↓
Malicious Domain / URL
     ↓
Fake Website
     ↓
Victim
     ↓
Credential Theft
     ↓
Collected Information
