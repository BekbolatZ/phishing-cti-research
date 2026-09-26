# Data Source Mapping

## Overview

Multiple OSINT sources were used to investigate the phishing infrastructure associated with `delivery-usps.vip`.

Each source provides different types of information. The sources were therefore used together to improve the coverage of the investigation.

## Data Source Mapping

| Data Source | Data Collected | Purpose | Result |
|---|---|---|---|
| VirusTotal | Domain reputation, vendor detections, DNS records, passive DNS, SSL certificates | Identify historical and current relationships associated with the domain | Multiple phishing/malicious classifications and historical infrastructure relationships |
| Shodan | Publicly indexed IP and service information | Investigate infrastructure associated with historical IP addresses | No results found for the three investigated IP addresses |
| Maltego | Entity and relationship visualization | Visualize and investigate relationships between infrastructure entities | Graph created, but useful automated Transforms were unavailable |
| Public Threat Intelligence Reports | Phishing campaign information and IOCs | Identify relevant indicators for investigation | `delivery-usps.vip` was selected as the primary investigation domain |

## Investigated Indicators

The main indicators collected during the investigation were:

### Domain

`delivery-usps.vip`

### Historical IP Addresses

- `43.135.155.184`
- `8.209.202.142`
- `47.245.39.108`

### Historical SSL Certificate Relationships

- `usps-redelivery.art`
- `*.easyerin.com`

## Source Correlation

The collected information can be represented as:

```text
Public Threat Intelligence
          |
          v
   delivery-usps.vip
          |
          v
      VirusTotal
          |
     +----+----+
     |         |
     v         v
Historical    SSL
IP addresses  certificates
     |
     v
   Shodan
     |
     v
No indexed results
     
Maltego
     |
     v
Relationship visualization
