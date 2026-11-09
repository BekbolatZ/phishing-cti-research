# Week 10 — Learning APT Techniques: APT29 (Cozy Bear / Midnight Blizzard)

**Course:** Introduction to Threat Hunting (ITH), Astana IT University
**Project topic:** CTI analysis of phishing infrastructure (`delivery-usps.vip`)
**Syllabus task (section 3.3, Week 10):** analyse the TTPs of APT29 or APT41 and map the observed techniques to the MITRE ATT&CK framework. Sources: Mandiant/FireEye reports, CrowdStrike Global Threat Report.

This week is research-based (no lab). Every factual claim is attributed to a public source; see section 8.

---

## 1. Why APT29

We chose **APT29** over APT41 because APT29 is one of the most prolific **spearphishing** actors, and our whole project is about a phishing campaign (`delivery-usps.vip`). APT29's real techniques line up almost one-to-one with what we studied and emulated in Weeks 6–9, so this week closes the loop: we show that our lab work mirrors a real-world adversary.

## 2. Who is APT29

| Item | Detail | Source |
|---|---|---|
| ATT&CK group ID | **G0016** | MITRE ATT&CK |
| Aliases | Cozy Bear, Midnight Blizzard, NOBELIUM, The Dukes, Dark Halo, UNC2452 | darkrelay / MITRE |
| Attribution | Russian state-sponsored espionage, linked to the **Foreign Intelligence Service (SVR)** | darkrelay |
| Active since | at least 2008 | darkrelay |
| Notable operations | SolarWinds / SUNBURST supply-chain compromise (2020), Microsoft/HPE intrusions, ongoing diplomatic spearphishing | public reporting |

APT29 is an **espionage** actor: its goal is long-term, stealthy access to governments, diplomats and tech companies, not immediate financial gain.

## 3. Case study — the "wine-tasting" spearphishing campaign (Jan 2025)

A concrete, recent campaign that matches our project almost exactly (Check Point Research, published 15 Apr 2025):

| Stage | What APT29 did |
|---|---|
| Lure | Emails impersonating a European foreign-affairs ministry, inviting targets to wine-tasting / diplomatic dinner events (subjects like "Wine Event", "For Ambassador's Calendar") |
| Delivery | Each email contained a **malicious link** whose domain matched the sender's domain (lookalike infrastructure) |
| User action | Clicking the link downloaded **`wine.zip`**; some links redirected to the real ministry website to look credible |
| Payload | A new backdoor, **GrapeLoader**, leading to a **WineLoader** variant |
| Evasion | The download only activated under certain times/locations; the server resisted scanners and sandboxes |
| Target | Diplomats and embassies across Europe |

**This is the same chain our project studied:** a lookalike domain → spearphishing **link** → user click → a file is **downloaded** onto the host → backdoor. Compare with our `delivery-usps.vip` lure and the Week 9 `curl` download.

## 4. APT29 TTPs mapped to ATT&CK

Compiled from MITRE G0016 and the darkrelay profile. (These are techniques APT29 is reported to use; not every one appears in every campaign.)

| Tactic | Technique | ID |
|---|---|---|
| Initial Access | Spearphishing Attachment | T1566.001 |
| Initial Access | **Spearphishing Link** | **T1566.002** |
| Initial Access | Valid Accounts: Cloud Accounts | T1078.004 |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 |
| Execution | Windows Management Instrumentation | T1047 |
| Execution | **User Execution** | **T1204** |
| Persistence | Account Manipulation | T1098 |
| Persistence | Create Account | T1136 |
| Persistence | Registry Run Keys / Startup Folder | T1547.001 |
| Credential Access | Brute Force: Password Spraying | T1110.003 |
| Credential Access | **OS Credential Dumping** | **T1003** |
| Defense Evasion | Use Alternate Authentication Material | T1550 |
| Defense Evasion | Impersonation | T1656 |
| Command and Control | Application Layer Protocol (HTTPS) | T1071 |
| Command and Control | Proxy: External Proxy | T1090.002 |
| Command and Control | **Ingress Tool Transfer** | **T1105** |
| Exfiltration | Exfiltration Over C2 Channel | T1041 |

Bold rows are the techniques our group already emulated in Weeks 6–9.

## 5. How APT29 maps onto our project (the main point)

| APT29 real technique | Where we emulated it |
|---|---|
| T1566.002 Spearphishing Link | Week 6 — phishing link to `delivery-usps.vip`, detected in Packetbeat |
| T1204.001 Malicious Link (user click) | Week 6 — simulated click + fake login page |
| T1105 Ingress Tool Transfer | Week 9 — `curl` download (APT29 used `wine.zip`) |
| T1003.008 OS Credential Dumping | Week 9 — read of `/etc/shadow`, caught by Auditbeat |
| T1046 Network Service Discovery (post-compromise) | Week 7 — CAR-2021-01-001 port-scan detection |

So across the project we reproduced and **detected** a realistic slice of APT29's kill chain, from the phishing link to post-compromise actions.

## 6. ATT&CK Navigator layer

File: [`apt29-navigator-layer.json`](apt29-navigator-layer.json). Open it in the ATT&CK Navigator (**+ → Open Existing Layer → Upload from local**).
- **Red** = techniques we emulated in Weeks 6–9.
- **Blue** = other APT29 techniques from public reporting.

MITRE also publishes an official APT29 layer: in the Navigator, **Create New Layer → search icon → "APT29" (G0016) → select** to load the full set.

*(Take a screenshot of the opened layer and save it as `screenshots/01-apt29-navigator.png`.)*

## 7. Limitations

- Based entirely on **public reporting**; APT29 campaigns evolve and some attribution is debated.
- A group's ATT&CK technique list is cumulative across years and campaigns — not every technique is used every time.
- We did not reverse-engineer GrapeLoader/WineLoader ourselves; the malware details come from Check Point's analysis.

## 8. References

- MITRE ATT&CK — APT29 (G0016): https://attack.mitre.org/groups/G0016/
- Check Point Research — "Unmasking APT29: the sophisticated phishing campaign targeting European diplomacy" (15 Apr 2025): https://blog.checkpoint.com/research/unmasking-apt29-the-sophisticated-phishing-campaign-targeting-european-diplomacy/
- DarkRelay — "APT29 (Midnight Blizzard): Operations, IOCs, Tactics, Detection Strategies": https://www.darkrelay.com/post/apt29-midnight-blizzard-operations-iocs-detection-strategies
- MITRE ATT&CK Navigator: https://mitre-attack.github.io/attack-navigator/
- CISA / Mandiant / CrowdStrike public reporting on APT29 (background)
- Course syllabus ITH 2026–2027, section 3.3, Week 10
- Previous work in this repository: `06-ATTACK-Framework`, `07-MITRE-CAR`, `09-Atomic-Red-Team`

**AI use:** the report structure, source research and the Navigator layer were prepared with the help of Claude (Anthropic). Factual claims are attributed to the public sources above and should be verified against them before submission.
