# Week 7 — MITRE CAR: implementing CAR-2021-01-001 "Identifying Port Scanning Activity" in the Elastic Stack

**Course:** Introduction to Threat Hunting (ITH), Astana IT University
**Project topic:** CTI analysis of phishing infrastructure (`delivery-usps.vip`)
**Syllabus task (section 3.3, Week 7):** select an analytic from MITRE CAR, implement it in a SIEM and map it to the related ATT&CK techniques.
**Lab:** Kali Linux VM (VirtualBox), Elasticsearch 8.19.23, Kibana, Packetbeat 8.19.23

All results below come from our own lab run. Times shown in the Kibana screenshots are in the VM browser's time zone (UTC-5).

---

## 1. Summary

| Item | Result |
|---|---|
| CAR analytic | CAR-2021-01-001 — Identifying Port Scanning Activity |
| ATT&CK technique | T1046 Network Service Discovery (tactic: Discovery, TA0007) |
| Data source | Packetbeat network flow records (`event.dataset: flow`) |
| Implementation | ES\|QL query in Kibana Discover, then a scheduled Kibana alerting rule (Elasticsearch query, ES\|QL) |
| Baseline (normal traffic, 15 min) | highest value: 4 distinct destination ports from one source |
| Simulated scan (nmap, ports 20–40) | source `127.0.0.1` reached 23 distinct destination ports |
| Detection | the threshold query returned only `127.0.0.1`; the rule raised an **Active** alert |

## 2. Why this analytic

We reviewed the full CAR analytic list (https://car.mitre.org/analytics/). CAR has **no analytic for phishing links, DNS or web proxy data**. The only CAR analytic mapped to User Execution (CAR-2021-05-002, Batch File Write to System32) is Windows-only, and our lab sensor is a Linux VM that collects network data. So CAR cannot be applied directly to the initial-access step studied in Week 6.

We therefore used CAR for the **next step of the same attack story**. CAR-2021-01-001 describes it: after compromising an initial machine, adversaries commonly try to move laterally, and the first step is often host, port and service scanning of the internal network with tools such as Nmap or Cobalt Strike.

```
Week 4 / Week 6:   phishing link (T1566.002) -> user clicks (T1204.001) -> credentials / foothold
                                                                              |
Week 7:                                                                       v
                             the compromised host scans the internal network (T1046)
                                          ^-- detected by CAR-2021-01-001
```

The analytic also fits our lab: its platforms include **Linux**, its information domain is **Network** with data subtype **Flow**, and Packetbeat can produce flow records without an endpoint agent.

## 3. The CAR analytic

Source: https://car.mitre.org/analytics/CAR-2021-01-001/

| Field | Value (from car.mitre.org) |
|---|---|
| ID / name | CAR-2021-01-001 — Identifying Port Scanning Activity |
| Submission date | 2020/10/23 |
| Contributor | Cyware Labs |
| Information domain / data subtype | Network / Flow |
| Analytic type | Situational Awareness |
| Platforms | Windows, Linux |
| ATT&CK | T1046 Network Service Discovery — tactic Discovery (TA0007) — level of coverage **Moderate** |
| D3FEND | D3-CAA Connection Attempt Analysis |
| Data model | `flow` / `start` / `dest_ip` |

**Idea of the analytic.** During a scan, one machine contacts many ports on other hosts in a short time. A normal host talks to a small, stable set of ports.

**Reference implementation published in CAR (Splunk):**

```
sourcetype='firewall_logs' dest_ip = 'internal_subnet' | stats dc(dest_port) as pcount by src_ip | where pcount >5
```

In words: for each source IP, count the distinct destination ports, and report sources with more than 5.

## 4. Lab setup for this analytic

### 4.1 Enabling flow records in Packetbeat

Packetbeat was already collecting DNS and HTTP (Weeks 5–6). We added flow reporting to `/etc/packetbeat/packetbeat.yml` (after making a backup):

```yaml
packetbeat.flows:
  timeout: 30s
  period: 10s
```

`sudo packetbeat test config` returned `Config OK`, and the service was restarted (`active`).

### 4.2 Checking the data

In Discover, the query `event.dataset : "flow"` returned **1,995 flow events in 15 minutes**, so flow collection works.

![Flow events in Discover](screenshots/01-flow-events.png)

We opened one event (JSON view) to confirm the field names needed by the analytic: `source.ip`, `destination.ip`, `destination.port` and `network.transport`. They exist with these exact names, so no field mapping was needed.

![Field names in a flow event](screenshots/02-flow-fields-json.png)

### 4.3 Translating the CAR logic to Elastic (ES|QL)

| CAR / Splunk element | Our Elastic equivalent |
|---|---|
| `sourcetype='firewall_logs'` | `FROM packetbeat-*` with `event.dataset == "flow"` |
| `dest_ip = 'internal_subnet'` | not applied in the lab (see limitations) |
| `stats dc(dest_port) as pcount by src_ip` | `STATS pcount = COUNT_DISTINCT(destination.port) BY source.ip` |
| `where pcount > 5` | `WHERE pcount > 5` |

Final query:

```esql
FROM packetbeat-*
| WHERE event.dataset == "flow" AND destination.port IS NOT NULL
| STATS pcount = COUNT_DISTINCT(destination.port) BY source.ip
| WHERE pcount > 5
```

`destination.port IS NOT NULL` removes flows without ports (for example ICMP from `ping`). The time window is taken from the Kibana time picker (Discover) or the rule's time window (15 minutes).

## 5. Test procedure and results

### 5.1 Baseline — normal traffic before the scan

To know what "normal" looks like, we first ran the query **without** the threshold, sorted by `pcount` (time range: last 15 minutes):

```esql
FROM packetbeat-*
| WHERE event.dataset == "flow" AND destination.port IS NOT NULL
| STATS pcount = COUNT_DISTINCT(destination.port) BY source.ip
| SORT pcount DESC
| LIMIT 10
```

| source.ip | pcount (distinct destination ports) |
|---|---|
| 10.0.2.15 (the VM's own address) | 4 |
| 127.0.0.1 | 2 |
| fd00::3897:3b76:6f45:4cd5 | 2 |
| ::1 | 1 |

The highest normal value was **4**, below the CAR threshold of 5.

![Baseline](screenshots/03-baseline-esql.png)

### 5.2 Simulated attack — port scan

Script: [`simulate_portscan.sh`](simulate_portscan.sh). It runs an nmap TCP connect scan of ports 20–40 (21 ports) against the lab VM itself (`127.0.0.1`). Only our own machine was scanned.

```bash
bash simulate_portscan.sh          # nmap -sT -Pn -n -p 20-40 127.0.0.1
```

Note: on the first attempt the query did not change, because the script file had not been created in `~/ith` (`No such file or directory`). After recreating the file and running it, the scan appeared in the data.

### 5.3 Query after the scan

The same baseline query, run after the scan:

| source.ip | pcount before | pcount after |
|---|---|---|
| **127.0.0.1** | 2 | **23** |
| 10.0.2.15 | 4 | 4 |
| fd00::3897:3b76:6f45:4cd5 | 2 | 2 |
| 34.107.243.93 | — | 1 |

`127.0.0.1` jumped from 2 to 23. The value matches what we expect: 21 ports from the scan (20–40) plus the 2 ports this address already used in normal traffic. The other sources did not change.

![After the scan](screenshots/04-esql-after-scan.png)

### 5.4 Query with the CAR threshold

With `WHERE pcount > 5` the query returned **exactly one result: `127.0.0.1` with `pcount = 23`**. All normal sources were filtered out.

![Threshold query](screenshots/05-esql-threshold.png)

## 6. Implementing the analytic as a SIEM rule

### 6.1 Problems met and how they were solved

1. **Security → Rules (Detection rules / SIEM)** did not allow creating a rule. Kibana showed *"Detection engine permissions required"*, although we were logged in as the `elastic` superuser.

   ![Detection engine message](screenshots/06-error-detection-engine.png)

2. **Stack Management → Rules** showed the real cause: *"Additional setup required — You must configure an encryption key to use Alerting."*

   ![Encryption key required](screenshots/07-error-encryption-key.png)

3. **Fix:** we added an encryption key (a random 32-character value) to `/etc/kibana/kibana.yml` and restarted Kibana (a backup of the file was made first; the key itself is not published):

   ```yaml
   xpack.encryptedSavedObjects.encryptionKey: "<random 32-character key>"
   ```

   After the restart, rule creation worked.

### 6.2 The rule

Created in **Stack Management → Rules → Create rule → Elasticsearch query → ES|QL**:

| Setting | Value |
|---|---|
| Rule name | CAR-2021-01-001 Port Scanning from single source |
| Rule type | Elasticsearch query (ES\|QL) |
| Query | the ES\|QL query from section 4.3 |
| Time field | `@timestamp` |
| Time window | 15 minutes |
| Runs every | 1 minute |
| Tags | `CAR`, `T1046`, `Week 7` |
| Actions | none (alerts are shown in Kibana) |

This rule type has no built-in ATT&CK field, so the mapping to T1046 is recorded in the tags and in the rule name.

![Rule details](screenshots/08-rule-details.png)

### 6.3 Alert

After the scan was repeated, the rule produced an **Active** alert:

- Rule status: **Enabled**, last response **Succeeded**, runs every 1 min.
- Alert: **Active**, started Nov 2, 2026 @ 02:50:26 (UTC-5).
- Reason: *"Document count is 1 in the last 15m"* — the query returned one row above the threshold. The same query in Discover (section 5.4) shows that this row is the scanning source `127.0.0.1`.

![Rule and active alert](screenshots/09-rule-alert.png)

## 7. Mapping and assessment

| Element | Value |
|---|---|
| CAR analytic | CAR-2021-01-001 Identifying Port Scanning Activity |
| ATT&CK technique detected | T1046 Network Service Discovery |
| ATT&CK tactic | Discovery (TA0007) |
| Cyber Kill Chain stage | after Exploitation / Installation: internal reconnaissance from a compromised host |
| Link to Week 4 | Week 4 mapped *Reconnaissance* to T1595 Active Scanning. T1595 is **external** scanning before the attack; T1046 is **internal** discovery after compromise. They are related but different, and this analytic covers T1046 only. |
| Link to Week 6 | follows T1566.002 → T1204.001 once the victim machine is controlled by the attacker |

**What the analytic detects well**
- Fast, wide port scans from a single source.
- It needs only flow data, no endpoint agent.

**What it does not detect**
- Slow scans spread over hours (each 15-minute window stays below the threshold).
- Host sweeps (one port on many hosts): the analytic counts ports, not hosts.
- Scans split across several source addresses.
- CAR itself rates its coverage of T1046 as **Moderate**.

**False positives**
- Vulnerability scanners and monitoring systems.
- Busy servers and workstations: in our quiet lab the highest normal value was 4, very close to the threshold of 5. On a real network, browsers and services would often exceed 5, so the threshold must be tuned.

**Difference from the CAR reference implementation**
- CAR's Splunk example uses firewall logs and restricts destinations to the internal subnet; we used Packetbeat flow records and did not filter by subnet.
- The detection logic (distinct destination ports per source, threshold > 5) is the same.

## 8. Recommendations

- Restrict the rule to internal destination subnets, as in the original CAR query, and allowlist approved scanners.
- Raise the threshold and choose the time window from a baseline of the real network (5 is an illustrative value).
- Add an action (email, Slack, index) so alerts reach analysts.
- Add endpoint telemetry (Auditbeat or Elastic Agent) to see which process started the scan; flow data cannot show this.
- Correlate with Weeks 5–6: raise priority when a host that contacted `delivery-usps.vip` later triggers this rule.

## 9. Limitations

- One lab VM; the scan was generated by us against our own machine (`127.0.0.1`), so the source is the loopback address, not a real internal host.
- Packetbeat also records its own traffic and Kibana/Elasticsearch traffic, which is part of the baseline.
- The Security app detection rule was not used; the analytic was implemented as a Kibana alerting rule (Elasticsearch query, ES|QL), and the ATT&CK mapping is in tags.
- CAR has no phishing-specific analytic, so Week 7 covers the post-compromise step, not the phishing step itself.

## 10. Files in this folder

```
07-MITRE-CAR/
├── README.md
├── simulate_portscan.sh
└── screenshots/
    ├── 01-flow-events.png              flow events in Discover (1,995 in 15 min)
    ├── 02-flow-fields-json.png         field names in a flow event
    ├── 03-baseline-esql.png            baseline before the scan
    ├── 04-esql-after-scan.png          127.0.0.1 = 23 after the scan
    ├── 05-esql-threshold.png           threshold query: only 127.0.0.1
    ├── 06-error-detection-engine.png   Security app message
    ├── 07-error-encryption-key.png     encryption key required
    ├── 08-rule-details.png             rule name and tags
    └── 09-rule-alert.png               enabled rule with active alert
```

## 11. References

- MITRE CAR — https://car.mitre.org/
- CAR analytic list — https://car.mitre.org/analytics/
- CAR-2021-01-001 Identifying Port Scanning Activity — https://car.mitre.org/analytics/CAR-2021-01-001/
- MITRE ATT&CK T1046 Network Service Discovery — https://attack.mitre.org/techniques/T1046/
- MITRE D3FEND D3-CAA Connection Attempt Analysis — https://d3fend.mitre.org/technique/d3f:ConnectionAttemptAnalysis
- Elastic documentation — ES|QL, Packetbeat flows, Kibana alerting (Elasticsearch query rule)
- Course syllabus ITH 2026–2027, section 3.3, Week 7
- Previous work in this repository: `04-Cyber-Kill-Chain`, `05-Threat-Hunting-Concept`, `06-ATTACK-Framework`

**AI use:** the report structure, queries and helper script were prepared with the help of Claude (Anthropic). All lab steps, results and screenshots come from our own environment.
