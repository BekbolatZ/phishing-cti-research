# Week 8 — Adversary Emulation Plan

## 1. Overview

This assignment focuses on developing an adversary emulation plan based on the MITRE ATT&CK Framework.

The scenario continues the previous investigation of phishing infrastructure associated with the domain `delivery-usps.vip`.

The objective is to prepare a controlled adversary emulation scenario, identify relevant attacker techniques, and explore MITRE CALDERA as a platform for testing defensive capabilities.

## 2. Objectives

- Understand the concept of adversary emulation.
- Develop an attack scenario using MITRE ATT&CK.
- Identify relevant attacker tactics and techniques.
- Install and explore MITRE CALDERA.
- Prepare a controlled agent deployment.
- Identify possible defensive measures against the selected techniques.

## 3. Tools and Environment

| Tool | Purpose |
|---|---|
| MITRE CALDERA 5.3.0 | Adversary emulation platform |
| MITRE ATT&CK | Framework for classifying attacker behavior |
| Docker Desktop | Running CALDERA in a container |
| Windows 11 | Local testing environment |
| Kali Linux | Additional testing environment |
| Git | Downloading and managing CALDERA source code |

## 4. Attack Scenario

The scenario represents a phishing-related attack against an organization.

The assumed initial access vector is a phishing message impersonating a delivery service. The following stages describe possible activities after a user interacts with a malicious message.

The scenario is based on the previously investigated phishing infrastructure associated with `delivery-usps.vip`.

All proposed activities are intended for a controlled laboratory environment. No real phishing emails, external targets, or sensitive data are used.

## 5. MITRE ATT&CK Mapping

| Attack Stage | Technique | ID | Description |
|---|---|---|---|
| Initial Access | Phishing | T1566 | Assumed phishing entry vector |
| Execution | PowerShell | T1059.001 | Command execution through PowerShell |
| Persistence | Scheduled Task | T1053.005 | Scheduled task creation |
| Collection | Data from Local System | T1005 | Accessing local test files |
| Exfiltration | Exfiltration Over C2 Channel | T1041 | Planned controlled data-transfer scenario |

**Note:** These techniques describe the proposed attack scenario. Their inclusion in this table does not mean they were successfully executed. Phishing (T1566) represents the assumed initial access vector and was not simulated.

## 6. Adversary Emulation Plan

The planned workflow consists of the following steps:

1. Prepare an isolated testing environment.
2. Install and configure MITRE CALDERA.
3. Explore the CALDERA interface and available plugins.
4. Prepare the Sandcat agent deployment configuration.
5. Select an adversary profile based on relevant ATT&CK techniques.
6. Execute selected harmless simulation abilities, if the agent is successfully connected.
7. Review the results and identify defensive recommendations.

## 7. Practical Implementation

**Status: Partially completed.**

The following activities were completed:

- Downloaded the official MITRE CALDERA repository.
- Installed and configured Docker Desktop.
- Started the CALDERA 5.3.0 container.
- Verified that the CALDERA web interface was accessible.
- Explored the available plugins, adversaries, and abilities.
- Configured the Sandcat agent deployment parameters.

**Limitation encountered:**

The Sandcat agent deployment was not completed successfully. Windows Defender blocked the generated PowerShell deployment script because it was identified as potentially malicious content.

Additional troubleshooting was performed in Kali Linux, but a successful agent connection was not established.

Therefore, no adversary emulation operation was executed and no successful simulation results are claimed.

## 8. Detection and Defensive Measures

Possible defensive measures for the proposed attack activities include:

- Monitoring PowerShell execution and command-line activity.
- Detecting suspicious scheduled task creation.
- Monitoring access to sensitive files.
- Analyzing unusual network connections.
- Using EDR and SIEM solutions to correlate security events.
- Applying network segmentation and access controls.

## 9. Conclusion

This assignment provided practical experience with installing and exploring MITRE CALDERA and developing an adversary emulation plan based on MITRE ATT&CK.

Although the CALDERA server was successfully deployed, the Sandcat agent could not be registered because its deployment was blocked by Windows Defender.

The assignment therefore demonstrates the preparation of an adversary emulation scenario and the configuration of the testing platform, but does not claim successful execution of the planned attack techniques.

## 10. Sources

- MITRE ATT&CK: https://attack.mitre.org/
- MITRE CALDERA: https://github.com/mitre/caldera
- CALDERA Documentation: https://caldera.readthedocs.io/
- MITRE ATT&CK Navigator: https://mitre-attack.github.io/attack-navigator/
- OpenAI ChatGPT: https://chatgpt.com/ — Used as an auxiliary tool for understanding technical concepts, troubleshooting Docker and CALDERA configuration, and preparing the adversary emulation plan.
