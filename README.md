# CVE_Compass Project README

## Overview

This CVE Compass is an end-to-end Azure data engineering platform that identifies which publicly reported software vulnerabilities affect an organization’s computers, servers, and applications. 

It demonstrates how a data engineer collects, stores, cleans, matches, tests, and delivers complex cybersecurity data through a production-style cloud pipeline. It also solves a realistic business problem by helping security teams decide which vulnerable systems should be patched first instead of treating every published vulnerability equally. For employers, the project provides evidence of Python, advanced SQL, PySpark, Azure, data modeling, incremental processing, data quality, monitoring, CI/CD, and technical documentation skills. Because the company assets and patch records are synthetically generated, the project remains safe, legal, publicly shareable, and suitable for a professional portfolio.

## Personal Documentation

### Aug 14


### Got a sample snippet of NVD CVE data (10 cve recordings).

__Useful Paths__

CVE_ID -> vulnerabilities[i].cve.id

Description -> vulnerabilities[i].cve.descriptions[0].value

Severity -> vulnerabilities[i].cve.metrics.cvssMetricV2[0].baseSeverity 

Affected Product -> vulnerabilities[i].cve.configurations[0].nodes[0].cpeMatch[0].criteria

Note: cvssMetricV2 is mostly 1990s. Newer ones are V3 or V4


### Design Synthetic Installed Software

This is the "other side" of CVE matching. NVD tells us which products a CVE affects via CPE (`vendor` / `product` / `version`). Our fake company inventory must store the same three ideas so we can join them later.

Example rows (made-up packages on made-up machines):

```json
[
  {
    "asset_id": "ASSET-001",
    "software_vendor": "openssl",
    "software_name": "openssl",
    "installed_version": "1.0.2",
    "last_observed_timestamp": "2026-08-01T12:00:00Z"
  },
  {
    "asset_id": "ASSET-001",
    "software_vendor": "apache",
    "software_name": "http_server",
    "installed_version": "2.4.49",
    "last_observed_timestamp": "2026-08-01T12:00:00Z"
  },
  {
    "asset_id": "ASSET-002",
    "software_vendor": "google",
    "software_name": "chrome",
    "installed_version": "126.0.6478.126",
    "last_observed_timestamp": "2026-08-02T09:30:00Z"
  }
]
```

Field meanings:
- `asset_id` — which machine this software sits on (links to the asset inventory later)
- `software_vendor` — maps to CPE vendor (e.g. `openssl`, `apache`, `google`)
- `software_name` — maps to CPE product (e.g. `openssl`, `http_server`, `chrome`)
- `installed_version` — maps to CPE version
- `last_observed_timestamp` — when we last "saw" this install (useful for freshness later)

Note: names are lowercase / underscore-style on purpose so they look closer to CPE naming. Real matching is still messy; exact string match is the V1 goal.
