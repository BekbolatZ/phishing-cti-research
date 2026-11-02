# Week 6 — ATT&CK Framework: Spearphishing Link (T1566.002) applied to the USPS phishing case

**Course:** Introduction to Threat Hunting (ITH), Astana IT University
**Project topic:** CTI analysis of phishing infrastructure (`delivery-usps.vip`)
**Syllabus task (section 3.3, Week 6):** study one specific technique, simulate an attack and map the results to ATT&CK tactics and techniques.
**Tooling:** Elastic Stack 8.19 (Elasticsearch + Kibana) with Packetbeat on a Kali Linux VM.

> **Honesty note for the reader.** Everything in sections 1–3 comes from the official ATT&CK pages. Section 5 (results) contains only what was actually observed in our lab; cells marked `FILL IN` must be completed from your own screenshots before submitting.

---

## 1. Chosen technique

| Field | Value |
|---|---|
| Technique | **T1566.002 — Phishing: Spearphishing Link** |
| Parent | T1566 Phishing |
| Tactic | Initial Access (TA0001) |
| Platforms (per ATT&CK) | Identity Provider, Linux, macOS, Office Suite, SaaS, Windows |
| Source | https://attack.mitre.org/techniques/T1566/002/ |

**Description.** The adversary sends an email that contains a malicious link, hoping the recipient follows it. The link may lead to a credential-harvesting page, a malicious download, or an OAuth / device-code consent page that hands the attacker an access token.

**Why we chose it.** Our group topic is the USPS-themed phishing domain `delivery-usps.vip`. Week 4 mapped the *Delivery* stage of the Kill Chain to T1566; this week we study its link-based sub-technique in depth. ATT&CK also lists a data source of "Application Log Content" for the email side; the network side (what the user's machine does after clicking) is what our lab can observe.

**Related techniques used in this report**

| ID | Name | Tactic | Role in the scenario |
|---|---|---|---|
| T1204.001 | User Execution: Malicious Link | Execution | The user clicks the link. ATT&CK describes this as typically observed as follow-on behaviour from Spearphishing Link. |
| T1056 | Input Capture | Collection, Credential Access | The fake page captures what the user types. Mapped at parent level, same as Week 4. |

**Why not T1056.003 (Web Portal Capture)?** ATT&CK defines it as code installed on *externally facing portals* (for example a VPN login page) to capture credentials. A purpose-built fake page is not a modified legitimate portal, so we stay at the parent technique. This is a judgement call and can be discussed during the defence.

## 2. What ATT&CK says about detection and mitigation

- **Data source (ATT&CK):** DS0015 Application Log: Application Log Content — monitor third-party application, messaging or other artifacts that may send spearphishing emails with a malicious link.
- **Mitigation (ATT&CK):** M1017 User Training — train users to recognise social engineering and check URLs before visiting sites.
- **Real-world use (examples listed by ATT&CK):** APT29, APT3, APT32, FIN7 (typosquatted link), Kimsuky, TA505, Emotet, among others. FIN7 and Leviathan examples explicitly mention lookalike / typosquatted domains, which is the same pattern as `delivery-usps.vip`.
- **Related detection strategy for the follow-on step:** DET0066 (User Execution: Malicious Link) — click, suspicious egress, download or file write, follow-on activity.

*(Verify the mitigation and data-source IDs once more on the live ATT&CK page before the defence.)*

## 3. Lab environment

| Component | Details |
|---|---|
| Host | Kali Linux VM (VirtualBox), 6.4 GB RAM |
| Search / storage | Elasticsearch 8.19.23 |
| Interface | Kibana (Discover, KQL) |
| Sensor | Packetbeat 8.19.23 — DNS (port 53) and HTTP (ports 80, 8080) |
| Data view | `packetbeat` (`packetbeat-*`) |

Setup was documented in Week 5 (`05-Threat-Hunting-Concept`).

## 4. Attack simulation

Script: [`simulate_phishing.sh`](simulate_phishing.sh)

**Design (safe by construction).**
- The "phishing page" is a tiny Python web server on `127.0.0.1:8080`. The real malicious domain is **never contacted over HTTP**.
- Requests carry the header `Host: delivery-usps.vip`, so the HTTP events look like a visit to the campaign domain.
- Only the DNS lookup of `delivery-usps.vip` goes to the lab resolver. The domain may return `NXDOMAIN`; the query is still logged.
- `usps.com` and `google.com` are looked up as legitimate controls.
- All credentials are fake test values.

**Steps and what each represents**

| # | Action | Represents | ATT&CK |
|---|---|---|---|
| 1 | `nslookup delivery-usps.vip` ×3 | User clicks the link in the email; browser resolves the domain | T1566.002 → T1204.001 |
| 2 | `nslookup usps.com`, `google.com` | Legitimate controls | — |
| 3 | `GET /login` with `Host: delivery-usps.vip` | User opens the fake landing page | T1204.001 |
| 4 | `POST /login` with fake credentials | User submits the form; credentials reach the attacker | T1056 |

Run:

```bash
sudo systemctl start elasticsearch   # wait 1-2 min
sudo systemctl start kibana packetbeat
bash simulate_phishing.sh
```

**Limitation of the simulation.** It reproduces what the victim's machine does *after* the email arrives. The email itself (the T1566.002 technique proper) is not simulated, so the evidence below supports detection of the follow-on activity, not of the email delivery.

## 5. Observations in Kibana

Data view `packetbeat`, time range around the run. Field names can differ slightly; open one event and check its JSON if a query returns nothing.

| # | KQL query | What it should show |
|---|---|---|
| Q1 | `dns.question.name : "delivery-usps.vip"` | DNS lookups of the campaign domain |
| Q2 | `url.domain : "delivery-usps.vip"` | HTTP requests whose Host is the campaign domain |
| Q3 | `http.request.method : "POST" and url.path : "/login"` | The credential submission |
| Q4 | `dns.question.name : *usps* and not dns.question.registered_domain : "usps.com"` | Lookalike domains (hunt from Week 5) |

| Query | Events found | Source host | Screenshot |
|---|---|---|---|
| Q1 | 3 | `FILL IN` | `screenshots/01-dns.png` |
| Q2 | 2 (GET and POST) | `FILL IN` | `screenshots/02-http-get.png` |
| Q3 | 1 | `FILL IN` | `screenshots/03-http-post.png` |
| Q4 | 3 | `FILL IN` | `screenshots/04-lookalike.png` |
| Control (`dns.question.name : *usps*`) | 5 (3 x `delivery-usps.vip`, 2 x `usps.com`) | `FILL IN` | `screenshots/04b-control-usps.png` |

**Q1 - DNS lookups of the campaign domain**

![Q1](<img width="676" height="606" alt="Снимок экрана 2026-10-31 110230" src="https://github.com/user-attachments/assets/fc05c7ba-8395-4004-b975-85576df17a21" />)

**Q2 - HTTP requests with Host `delivery-usps.vip` (GET and POST)**

![Q2](<img width="677" height="531" alt="Снимок экрана 2026-10-31 110246" src="https://github.com/user-attachments/assets/fb34e08c-8467-4d0d-a6a0-c36de9466230" />)

**Q3 - credential submission (POST /login)**

![Q3](<img width="742" height="502" alt="Снимок экрана 2026-10-31 110258" src="https://github.com/user-attachments/assets/fde053fe-65b5-4cbd-97b3-277ca4d78d66" />)

**Q4 - lookalike domains, excluding legitimate `usps.com`**

![Q4](<img width="742" height="601" alt="Снимок экрана 2026-10-31 111114" src="https://github.com/user-attachments/assets/0963198a-98ad-43a3-98f3-6542f182740c" />)

**Control - all `*usps*` lookups, before excluding `usps.com`**

![Control](<img width="742" height="728" alt="Снимок экрана 2026-10-31 111159" src="https://github.com/user-attachments/assets/a3afd70b-7658-44c4-8cdc-e6f433bc6393" />)

**Analysis.**
- All three simulated victim-side steps were visible in the telemetry: the DNS lookups of the campaign domain (Q1, 3 events), the HTTP requests carrying `Host: delivery-usps.vip` (Q2, 2 events: GET and POST) and the credential submission to `/login` (Q3, 1 event). The simulation was run at about 05:53 UTC; Kibana displayed the events at 01:53 because the VM browser uses UTC-4 (EDT).
- The fields `url.domain`, `url.path` and `http.request.method` were populated for the HTTP events, so the queries worked without changes.
- The number of DNS events (3) equals the number of lookups of the campaign domain. The control domains `usps.com` and `google.com` did not appear in Q1.
- Control query `dns.question.name : *usps*` returned 5 events: 3 for `delivery-usps.vip` and 2 for the legitimate `usps.com`. Q4 (which excludes `dns.question.registered_domain : "usps.com"`) kept only the 3 phishing-domain events, so the exclusion works and the field `dns.question.registered_domain` is populated.
- Background noise such as `telemetry.elastic.co` did not appear in Q1-Q4 because these queries filter on specific domains; it would have to be excluded in broader hunts.

## 6. Mapping: simulation → Kill Chain → ATT&CK → evidence

| Simulated action | Kill Chain stage (Week 4) | ATT&CK tactic | ATT&CK technique | Evidence |
|---|---|---|---|---|
| DNS lookup after clicking the link | Delivery | Initial Access | T1566.002 | Q1 |
| Fake page opened | Exploitation | Execution | T1204.001 | Q2 |
| Fake credentials submitted | Actions on Objectives | Collection / Credential Access | T1056 | Q3 |

The mapping is analytical: it shows how lab artifacts line up with ATT&CK, not proof about the real threat actor.

## 7. ATT&CK Navigator layer

The layer was opened in the ATT&CK Navigator (https://mitre-attack.github.io/attack-navigator/, ATT&CK v20). T1566.002 Spearphishing Link (red), T1204.001 Malicious Link (orange) and T1056 Input Capture (blue) are highlighted. During the v19 to v20 layer-upgrade review, the IDs, names and tactics of T1566, T1204 and T1204.001 were unchanged; T1056 Input Capture appears with the same ID and name in the v20 matrix (Credential Access and Collection).

![ATT&CK Navigator layer](screenshots/05-navigator.png)

Layer file: [navigator-layer.json](navigator-layer.json)

## 8. Defensive recommendations

- Block or sinkhole confirmed IOCs (`delivery-usps.vip` and the three IPs from Week 3) at DNS and web proxy.
- Alert on lookalike brand domains in DNS (Q4 logic) with an allowlist for legitimate brand domains.
- Alert on HTTP `POST` to login-like paths on domains never seen before (Week 4 Hypothesis B).
- User training (M1017) and phishing-resistant MFA for the account-takeover step.

## 9. Limitations

- Single lab VM; the traffic was generated by us.
- The email delivery step is not simulated.
- Packetbeat sees HTTP metadata only on cleartext HTTP; real phishing pages almost always use HTTPS, where only DNS, SNI and flow metadata would be visible. This is why DNS-based detection matters.
- Mapping to ATT&CK is analytical; some choices (parent technique vs sub-technique) are judgement calls.

## 10. References

- MITRE ATT&CK T1566.002 — https://attack.mitre.org/techniques/T1566/002/
- MITRE ATT&CK T1204.001 — https://attack.mitre.org/techniques/T1204/001/
- MITRE ATT&CK T1056 / T1056.003 — https://attack.mitre.org/techniques/T1056/
- MITRE ATT&CK DET0066 — https://attack.mitre.org/detectionstrategies/DET0066
- ATT&CK Navigator — https://mitre-attack.github.io/attack-navigator/
- Course syllabus ITH 2026–2027, section 3.3, Week 6
- Previous work: `04-Cyber-Kill-Chain`, `05-Threat-Hunting-Concept`
