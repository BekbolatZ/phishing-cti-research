# Week 8 — Adversary Emulation Plan

## 1. Overview

This assignment focuses on creating an adversary emulation plan based on the MITRE ATT&CK Framework.

The scenario continues the previous investigation of phishing infrastructure associated with the domain `delivery-usps.vip`.

The main goal is to plan and perform controlled simulations of selected attacker techniques using MITRE CALDERA in an isolated laboratory environment.

## 2. Objectives

- Understand the concept of adversary emulation.
- Develop an attack scenario using MITRE ATT&CK.
- Identify relevant attacker tactics and techniques.
- Configure and explore MITRE CALDERA.
- Simulate selected attack activities in a controlled environment.
- Analyze the results and identify possible defensive measures.

## 3. Tools and Environment

| Tool | Purpose |
|---|---|
| MITRE CALDERA | Adversary emulation platform |
| MITRE ATT&CK | Framework for classifying attacker behavior |
| Docker Desktop | Running CALDERA containers |
| Windows 11 | Local testing environment |
| Git | Downloading and managing CALDERA source code |

## 4. Attack Scenario

The scenario represents a phishing-related attack against an organization.

The assumed initial access vector is a phishing message impersonating a delivery service. The following stages represent activities that may occur after a user interacts with a malicious message.

The practical simulation will use harmless test actions in an isolated environment. No real phishing emails, external targets, or sensitive data will be used.

## 5. MITRE ATT&CK Mapping

| Attack Stage | Technique | ID | Description |
|---|---|---|---|
| Initial Access | Phishing | T1566 | Phishing is used as the assumed entry vector in the scenario. |
| Execution | PowerShell | T1059.001 | Simulating command execution through PowerShell. |
| Persistence | Scheduled Task | T1053.005 | Demonstrating scheduled task creation in a controlled environment. |
| Collection | Data from Local System | T1005 | Accessing harmless test files. |
| Exfiltration | Exfiltration Over C2 Channel | T1041 | Planning a controlled data-transfer simulation. |

**Note:** Phishing (T1566) describes the scenario's assumed entry vector. It is not considered executed unless a separate practical test demonstrates it. The remaining techniques will be tested only if suitable safe CALDERA abilities are available.

## 6. Adversary Emulation Plan

The planned workflow consists of the following steps:

1. Prepare the isolated testing environment.
2. Install and configure MITRE CALDERA.
3. Deploy a CALDERA agent in the test environment.
4. Select an adversary profile based on relevant ATT&CK techniques.
5. Execute selected harmless simulation abilities.
6. Review the execution results.
7. Document observations and defensive recommendations.

## 7. Practical Implementation

**Status: In progress.**

The practical implementation will include:

- CALDERA installation using Docker.
- CALDERA server configuration.
- Agent deployment and connection verification.
- Selection of appropriate ATT&CK techniques.
- Execution of safe adversary emulation actions.
- Screenshots and analysis of the results.

Practical results will be added after the corresponding steps are completed.

## 8. Detection and Defensive Measures

Possible defensive measures for the simulated activities include:

- Monitoring PowerShell execution.
- Detecting suspicious scheduled task creation.
- Monitoring access to sensitive files.
- Analyzing unusual network connections.
- Using EDR and SIEM solutions to correlate security events.
- Applying network segmentation and access controls.

## 9. Expected Results

The expected outcome is a documented adversary emulation scenario demonstrating how selected MITRE ATT&CK techniques can be represented and tested using CALDERA.

The practical results will help evaluate whether the simulated activities can be detected and what security controls may reduce the associated risks.

## 10. Sources

- MITRE ATT&CK: https://attack.mitre.org/
- MITRE CALDERA: https://github.com/mitre/caldera
- CALDERA Documentation: https://caldera.readthedocs.io/
- MITRE ATT&CK Navigator: https://mitre-attack.github.io/attack-navigator/
- OpenAI ChatGPT: https://chatgpt.com/ — Used as an AI assistant for understanding technical concepts, troubleshooting Docker and CALDERA setup, and preparing the adversary emulation plan.
