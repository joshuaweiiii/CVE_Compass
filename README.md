# CVE_Compass Project README

## Overview

This CVE Compass is an end-to-end Azure data engineering platform that identifies which publicly reported software vulnerabilities affect an organization’s computers, servers, and applications. 

It demonstrates how a data engineer collects, stores, cleans, matches, tests, and delivers complex cybersecurity data through a production-style cloud pipeline. It also solves a realistic business problem by helping security teams decide which vulnerable systems should be patched first instead of treating every published vulnerability equally. For employers, the project provides evidence of Python, advanced SQL, PySpark, Azure, data modeling, incremental processing, data quality, monitoring, CI/CD, and technical documentation skills. Because the company assets and patch records are synthetically generated, the project remains safe, legal, publicly shareable, and suitable for a professional portfolio.

## Personal Documentation

### Aug 14


### Sample snippet of NVD CVE data (10 CVE Recordings)

__Useful Paths__

CVE_ID -> vulnerabilities[i].cve.id

Description -> vulnerabilities[i].cve.descriptions[0].value

Severity -> vulnerabilities[i].cve.metrics.cvssMetricV2[0].baseSeverity 

Affected Product (CPE) -> vulnerabilities[i].cve.configurations[0].nodes[0].cpeMatch[0].criteria

    CPE Format -> cpe : spec version : which part : vendor : product : product version : others

Note: cvssMetricV2 is mostly 1990s. Newer ones are V3 or V4


### Design Snippet of Synthetic Installed Softwares

Created synthetic softwares that have (`vendor` / `product` / `product version`), which matches to NVD criteria (`Affected Product`)

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
Synthetic Softwares Metadata: 
- `asset_id` — which machine has this software
- `software_vendor` — maps to CPE vendor 
- `software_name` — maps to CPE product
- `installed_version` — maps to CPE version
- `last_observed_timestamp` — most recent software inventory scan


### Design Snippet of Synthetic Asset Inventory

Created synthetic assets (machines), one row per machine. `asset_id` matches synthetic installed softwares (one asset -> many softwares)

```json
[
  {
    "asset_id": "ASSET-001",
    "hostname": "web-prod-01",
    "device_type": "server",
    "operating_system": "ubuntu",
    "department": "engineering",
    "business_criticality": "high",
    "internet_exposed": true,
    "asset_owner": "platform-team",
    "last_scan_timestamp": "2026-08-01T12:00:00Z"
  },
  {
    "asset_id": "ASSET-002",
    "hostname": "laptop-jwei",
    "device_type": "laptop",
    "operating_system": "macos",
    "department": "engineering",
    "business_criticality": "medium",
    "internet_exposed": false,
    "asset_owner": "joshua",
    "last_scan_timestamp": "2026-08-02T09:30:00Z"
  }
]
```
Synthetic Assets Metadata:
- `asset_id` — unique machine ID
- `hostname` — human readable name 
- `device_type` — server / laptop / workstation / etc.
- `operating_system` — what OS machine is using
- `department` — department who owns asset
- `business_criticality` — how important asset is for business (high / medium / low)
- `internet_exposed` — true if machine can be reached from internet
- `asset_owner` — person responsible for asset
- `last_scan_timestamp` — most recent full asset scan


### Design Snippet of Synthetic Patch Management

Created synthetic patch tracker. Tracks if specific CVE on specific asset has been fixed. Join keys: `asset_id` and `cve_id`.

```json
[
  {
    "asset_id": "ASSET-001",
    "cve_id": "CVE-2021-44228",
    "first_detected_timestamp": "2026-07-15T08:00:00Z",
    "patch_available": true,
    "patch_status": "patched",
    "patched_timestamp": "2026-07-20T16:30:00Z",
    "remediation_owner": "platform-team",
    "exception_reason": null
  },
  {
    "asset_id": "ASSET-001",
    "cve_id": "CVE-2021-41773",
    "first_detected_timestamp": "2026-08-01T12:00:00Z",
    "patch_available": true,
    "patch_status": "open",
    "patched_timestamp": null,
    "remediation_owner": "platform-team",
    "exception_reason": null
  },
  {
    "asset_id": "ASSET-002",
    "cve_id": "CVE-2024-0519",
    "first_detected_timestamp": "2026-07-28T10:00:00Z",
    "patch_available": true,
    "patch_status": "accepted_risk",
    "patched_timestamp": null,
    "remediation_owner": "joshua",
    "exception_reason": "legacy browser plugin; scheduled rebuild next quarter"
  }
]
```
Synthetic Patches Metadata:
- `asset_id` — which machine with problem
- `cve_id` — unique vulnerability ID
- `first_detected_timestamp` — time when asset was flagged for corresponding CVE
- `patch_available` — true if fix possible/created
- `patch_status` — `open` / `in_progress` / `patched` / `accepted_risk`
- `patched_timestamp` — when it was fixed (`null` if not fixed)
- `remediation_owner` — who assigned to fix it
- `exception_reason` — why `patch_status` = `accepted_risk` (otherwise `null`)


### Data Model

```text
┌─────────────┐         cve_id          ┌─────────────────┐
│     NVD     │─────────────────────────│  Patch records  │
│  (CVEs)     │                         │ asset_id+cve_id │
└──────┬──────┘                         └────────┬────────┘
       │                                         │
       │ match on                                │ asset_id
       │ vendor / product / version              │
       │                                         ▼
┌──────▼──────────────┐                 ┌─────────────────┐
│ Installed software  │──── asset_id ───│     Assets      │
│ asset_id + vendor/  │                 │  (machines)     │
│ product / version   │                 └─────────────────┘
└─────────────────────┘
```