# Week 2 - OSINT Data Collection

## Overview

This week focuses on collecting and analyzing Open Source Intelligence (OSINT) related to phishing infrastructure.

The investigation is part of the project:

**Cyber Threat Intelligence Analysis of Phishing Infrastructure**

The main objective is to understand how publicly available intelligence can be collected, correlated, and used to investigate malicious domains, URLs, IP addresses, hosting infrastructure, and relationships between different indicators.

## Objectives

- Perform OSINT data collection.
- Investigate phishing-related domains and URLs.
- Analyze indicators using VirusTotal.
- Investigate Internet-facing infrastructure using Shodan.
- Visualize relationships between entities using Maltego.
- Develop a data source mapping for further analysis.
- Document limitations and reliability of OSINT sources.

## Investigated Threat Intelligence Cases

Two publicly documented cases were selected as examples for the investigation:

1. USPS phishing campaign infrastructure.
2. APT41 malware delivery infrastructure involving phishing links and free hosting services.

The indicators used in this project were obtained from publicly available threat intelligence reports.

## Main Tools

- VirusTotal
- Shodan
- Maltego
- Public threat intelligence reports
- DNS and domain information

## Investigation Workflow

```text
Public Threat Intelligence Reports
              |
              v
        IOC Collection
              |
       +------+------+
       |             |
       v             v
  VirusTotal       Shodan
       |             |
       +------+------+
              |
              v
           Maltego
              |
              v
     Relationship Mapping
              |
              v
        CTI Analysis
