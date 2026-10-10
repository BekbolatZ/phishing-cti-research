# Week 5 — Threat Hunting Concept: Hypothesis-Driven Hunt for Phishing Infrastructure

**Course:** Introduction to Threat Hunting (ITH), Astana IT University
**Project topic:** CTI analysis of phishing infrastructure
**Case:** USPS-themed phishing campaign, domain `delivery-usps.vip`
**Tooling:** Elastic Stack (Elasticsearch + Kibana) with Packetbeat on a Kali Linux VM

---

## 1. Overview

In Weeks 1–4 we collected and analyzed intelligence about the phishing domain `delivery-usps.vip` (OSINT with VirusTotal and Shodan, IOC management in MISP, Cyber Kill Chain / MITRE ATT&CK mapping).

In Week 5 we move from *analysis* to *hunting*: we turn that intelligence into testable hypotheses, collect DNS telemetry in a SIEM-like environment, and execute hunt queries in Kibana (Discover, KQL).

## 2. Objectives

- Understand the threat hunting concept and the main hunting models.
- Build hypothesis-driven hunting scenarios based on our CTI.
- Deploy a working data collection and search environment (Elastic Stack).
- Execute hunt queries and document the results.
- Evaluate findings, false positives and limitations.

## 3. Hunting Models

| Model | Starting point | How we use it |
|---|---|---|
| **Intel-driven** | Known IOCs (domains, IPs) from CTI | Search telemetry for the IOCs collected in Weeks 2–3 |
| **Hypothesis-driven** | An assumption about attacker behavior (TTPs) | Search for brand-impersonating domains even if they are not yet known IOCs |

This week combines both: IOCs from our CTI feed the intel-driven hunt, and the attacker behavior seen in the campaign (domain impersonation) feeds the hypothesis-driven hunt.

## 4. Hunting Hypotheses

| ID | Hypothesis | Model | Kill Chain stage | ATT&CK |
|---|---|---|---|---|
| **H1** | If a host in our network contacted the known phishing domain, a DNS query for `delivery-usps.vip` will exist in the DNS telemetry. | Intel-driven | Delivery | T1566 Phishing |
| **H2** | If a user was lured by a lookalike domain not yet in our IOC list, DNS logs will contain domains with the brand keyword `usps` that are not the legitimate `usps.com`. | Hypothesis-driven | Delivery / Exploitation | T1566, T1204 User Execution |
| **H3** | If a host communicated directly with the infrastructure behind the domain, network telemetry will contain connections to the known IPs `43.135.155.184`, `8.209.202.142`, `47.245.39.108`. | Intel-driven | Command and Control | T1071 Application Layer Protocol |

Each hypothesis defines: what we expect to see, where we look (data source), and how we decide whether it is confirmed.

## 5. Lab Environment

| Component | Details |
|---|---|
| Host | Kali Linux VM (VirtualBox), 6.4 GB RAM |
| Search / storage | Elasticsearch 8.19.23 |
| UI / hunting interface | Kibana (Discover, KQL) |
| Data collection | Packetbeat 8.19.23 (DNS and HTTP protocols) |
| Index pattern | `packetbeat-*` |

> Wazuh (OpenSearch-based) was also available, but we used the Elastic Stack (ELK) as required by the course material.

### 5.1 Setup steps

1. **Installed Elasticsearch and Kibana** from the official Elastic 8.x APT repository.
2. **Tuned memory:** the VM initially had 1.9 GB RAM and froze. We increased it to 6.4 GB and limited the Elasticsearch heap to 1 GB (`/etc/elasticsearch/jvm.options.d/heap.options`).
3. **Connected Kibana to Elasticsearch** with an enrollment token and verification code, and reset the `elastic` user password.
4. **Installed and configured Packetbeat** to capture DNS (port 53) and HTTP traffic on all interfaces and ship it to Elasticsearch over HTTPS with CA verification.
5. **Validated the pipeline:** `packetbeat test config` and `packetbeat test output` returned `OK`; `packetbeat setup --index-management` completed.
6. **Created the `packetbeat` data view** (`packetbeat-*`, timestamp `@timestamp`) in Kibana.

Minimal Packetbeat configuration used (credentials omitted):

```yaml
packetbeat.interfaces.device: any
packetbeat.protocols:
- type: dns
  ports: [53]
- type: http
  ports: [80, 8080]
setup.kibana:
  host: "http://localhost:5601"
output.elasticsearch:
  hosts: ["https://localhost:9200"]
  username: "elastic"
  password: "<REDACTED>"
  ssl.certificate_authorities: ["/etc/elasticsearch/certs/http_ca.crt"]
```

![Kibana Discover with Packetbeat data](screenshots/01-discover-packetbeat-data.png)

## 6. Telemetry Generation

To create observable activity safely, we only performed **DNS lookups** (no browsing, no credential entry) from the lab VM:

```bash
for i in 1 2 3; do nslookup delivery-usps.vip; sleep 2; done
nslookup usps.com      # legitimate control
nslookup google.com    # legitimate control
```

The legitimate domains serve as a control group to evaluate false positives. The lookup of the malicious domain may return `NXDOMAIN` if it is no longer active; the DNS query itself is still recorded.

## 7. Hunt Queries and Results

All queries were run in Kibana Discover (KQL), data view `packetbeat`, time range *Last 1 hour*.

### H1 — Known phishing domain (intel-driven)

```
dns.question.name : "delivery-usps.vip"
```

- **Result:** `<number>` events, source host `10.0.2.15`.
- **Verdict:** `<Confirmed / Not confirmed>`

![H1 results](screenshots/02-h1-known-domain.png)

### H2 — Brand impersonation (hypothesis-driven)

```
dns.question.name : *usps* and not dns.question.registered_domain : "usps.com"
```

- **Result:** `<number>` events, domains found: `<list>`.
- **Verdict:** `<Confirmed / Not confirmed>`

![H2 results](screenshots/03-h2-brand-impersonation.png)

### H3 — Direct contact with known IPs (intel-driven)

```
destination.ip : ("43.135.155.184" or "8.209.202.142" or "47.245.39.108")
```

- **Result:** `<number>` events.
- **Verdict:** `<Confirmed / Not confirmed>`. A negative result is still a valid hunt outcome: it shows no direct contact with the listed IPs was observed in this dataset.

![H3 results](screenshots/04-h3-known-ips.png)

### Summary

| Hypothesis | Query field | Events | Outcome |
|---|---|---|---|
| H1 | `dns.question.name` | `<n>` | `<outcome>` |
| H2 | `dns.question.name`, `dns.question.registered_domain` | `<n>` | `<outcome>` |
| H3 | `destination.ip` | `<n>` | `<outcome>` |

## 8. Analysis

**True positives.** Queries for `delivery-usps.vip` generated by our own test lookups match H1 and H2 and show that the data source and queries work end to end.

**False positives and noise.**
- Background DNS traffic such as `telemetry.elastic.co` (generated by the Elastic Stack itself) appears in the dataset and must be excluded from broader hunts.
- The keyword `usps` may legitimately appear in unrelated domains; the `not registered_domain : "usps.com"` filter handles the main legitimate case but would need an allowlist in a production environment (e.g., other official USPS domains).

**Value of the approach.** H2 can detect lookalike domains that are *not yet* in any IOC list, which an intel-only search would miss.

## 9. Limitations

- The dataset is a single lab VM, not a real enterprise network, so volumes and baselines are not representative.
- Only DNS and HTTP metadata were collected; there is no endpoint (process, file) or email telemetry.
- The test activity was generated by us, so the hunt demonstrates method and tooling rather than discovering a real intrusion.
- The exact attacker actions after delivery (installation, C2, final objective) cannot be confirmed from DNS data alone.

## 10. Recommendations

- Turn H2 into a **Kibana detection rule** (scheduled query) alerting on brand-keyword domains outside an allowlist.
- Enrich DNS events with domain age (newly registered domain feed) to reduce noise, as in the Week 4 hypotheses.
- Add endpoint telemetry (Sysmon/Winlogbeat or Elastic Agent) and proxy/email logs to cover the Exploitation and Installation stages.
- Feed confirmed IOCs back into MISP and DNS/firewall blocklists to close the CTI loop.

## 11. Conclusion

We built a working hunting environment with the Elastic Stack, defined three hypotheses derived from our CTI work, and executed them as KQL hunt queries over DNS telemetry. The exercise demonstrates the full hunting loop: intelligence → hypothesis → data → query → analysis → improvement.

## 12. Repository Structure (this folder)

```
05-Threat-Hunting-Concept/
├── README.md
└── screenshots/
    ├── 01-discover-packetbeat-data.png
    ├── 02-h1-known-domain.png
    ├── 03-h2-brand-impersonation.png
    └── 04-h3-known-ips.png
```

## 13. References

- Course lecture materials, Week 5 — Threat Hunting Concept (Astana IT University)
- Elastic documentation — Kibana Discover and KQL; Packetbeat reference
- MITRE ATT&CK — https://attack.mitre.org/
- Lockheed Martin — Cyber Kill Chain
- Previous project work: `01-CTI-Fundamentals`, `02.-OSINT`, `03-Data-Processing-and-Exploitation`, `04-Cyber-Kill-Chain`
