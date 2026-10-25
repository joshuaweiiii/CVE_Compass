# CVE Compass — Development Notes

Learning log and design notes behind the project. For the project summary, results, and how to run it, see the [README](../README.md).

## Contents

- [1. NVD API Basics](#1-nvd-api-basics)
- [2. Useful NVD JSON Paths](#2-useful-nvd-json-paths)
- [3. Prototype: Hand-Written Synthetic Data](#3-prototype-hand-written-synthetic-data)
- [4. Prototype: First Matcher](#4-prototype-first-matcher)
- [5. NVD Week Profiling (Sept 1–7, 2026)](#5-nvd-week-profiling-sept-17-2026)
- [6. Generated Synthetic Data](#6-generated-synthetic-data)
- [7. Version-Range Matcher](#7-version-range-matcher)
- [8. Generated Patch Tickets](#8-generated-patch-tickets)
- [9. Git and Repo Lessons](#9-git-and-repo-lessons)
- [10. Open Issues / Future Improvements](#10-open-issues--future-improvements)

---

## 1. NVD API Basics

- Endpoint: `https://services.nvd.nist.gov/rest/json/cves/2.0`
- API key goes in the request **header** named exactly `apiKey` (not `api_key` — NVD silently ignores the wrong name and treats the request as anonymous).
- Key is stored in `~/.zshrc` as `export NVD_API_KEY="..."` and read with `os.environ.get("NVD_API_KEY")`. Never put it in code.
- Rate limits: 5 requests / 30 sec without a key, 50 with a key.
- Pagination: `resultsPerPage` (max 2,000) + `startIndex`. Loop until `startIndex >= totalResults`, adding `len(vulnerabilities)` each page.
- Date windows: `pubStartDate` and `pubEndDate` are required together, max 120 days apart, format `YYYY-MM-DDTHH:MM:SS.mmm`.
- Response `resultsPerPage` is how many came back, not how many were requested (page 2 of the week showed 204).

## 2. Useful NVD JSON Paths

| Field | Path |
|---|---|
| CVE ID | `vulnerabilities[i].cve.id` |
| Status | `vulnerabilities[i].cve.vulnStatus` (Analyzed, Modified, Deferred, Awaiting Analysis, Received, Rejected, ...) |
| Description | `vulnerabilities[i].cve.descriptions[0].value` |
| CVSS v3.1 score | `vulnerabilities[i].cve.metrics.cvssMetricV31[*].cvssData.baseScore` |
| CVSS v3.1 severity | `vulnerabilities[i].cve.metrics.cvssMetricV31[*].cvssData.baseSeverity` |
| Score type | `cvssMetricV31[*].type` — `Primary` (NVD) or `Secondary` (vendor / CNA) |
| Affected product (CPE) | `vulnerabilities[i].cve.configurations[*].nodes[*].cpeMatch[*].criteria` |
| Is it the vulnerable product? | `cpeMatch[*].vulnerable` (`true` = has the bug, `false` = platform it runs on) |
| Version range | `cpeMatch[*].versionStartIncluding` / `versionStartExcluding` / `versionEndIncluding` / `versionEndExcluding` |

CPE format: `cpe:2.3:part:vendor:product:version:...` — split on `:` → index 3 = vendor, 4 = product, 5 = version. Part is `a` (application), `o` (operating system), or `h` (hardware). When version is `*`, the real limits are in the range fields.

Notes:

- `cvssMetricV2` is mostly 1990s-era CVEs. Newer ones use V3.1 (and some V4).
- `configurations` only exists after NVD analysis — always check `"configurations" in cve` before reading it.

## 3. Prototype: Hand-Written Synthetic Data

First small versions of the company data, used to prove the joins work. Files now live in `prototype/data/`.

### Installed Software

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
  }
]
```

- `asset_id` — which machine has this software
- `software_vendor` — maps to CPE vendor
- `software_name` — maps to CPE product
- `installed_version` — maps to CPE version
- `last_observed_timestamp` — most recent software inventory scan

### Asset Inventory

Created synthetic assets (machines), one row per machine. `asset_id` matches synthetic installed softwares (one asset -> many softwares)

```json
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
}
```

- `asset_id` — unique machine ID
- `hostname` — human readable name
- `device_type` — server / laptop / workstation / etc.
- `operating_system` — what OS machine is using
- `department` — department who owns asset
- `business_criticality` — how important asset is for business (high / medium / low)
- `internet_exposed` — true if machine can be reached from internet
- `asset_owner` — team responsible for asset
- `last_scan_timestamp` — most recent full asset scan

### Patch Management

Created synthetic patch tracker. Tracks if specific CVE on specific asset has been fixed. Join keys: `asset_id` and `cve_id`.

```json
{
  "asset_id": "ASSET-001",
  "cve_id": "CVE-2021-41773",
  "first_detected_timestamp": "2026-08-01T12:00:00Z",
  "patch_available": true,
  "patch_status": "open",
  "patched_timestamp": null,
  "remediation_owner": "platform-team",
  "exception_reason": null
}
```

- `asset_id` — which machine with problem
- `cve_id` — unique vulnerability ID
- `first_detected_timestamp` — time when asset was flagged for corresponding CVE
- `patch_available` — true if fix possible/created
- `patch_status` — `open` / `in_progress` / `patched` / `accepted_risk`
- `patched_timestamp` — when it was fixed (`null` if not fixed)
- `remediation_owner` — who is assigned to fix it
- `exception_reason` — why `patch_status` = `accepted_risk` (otherwise `null`)

## 4. Prototype: First Matcher

`prototype/scripts/match_cve.py` matched one Apache CVE (CVE-2021-41773) plus 10 sample CVEs against the hand-written data.

- Matching was a **substring check**: vendor, product, and version all `in` the CPE criteria string.
- Joined assets by `asset_id` and patches by `(asset_id, cve_id)`; missing patch row → `open`.
- Priority rule (still used today):
  - `done` if patched
  - `patch_now` if open **and** CRITICAL **and** internet-exposed **and** high business criticality
  - otherwise `review`
- Result: 2 exposures (ASSET-001 → `patch_now`, ASSET-002 → `review`). Proved the data model works end to end.

Why it was replaced: real CPEs usually have version `*` with ranges in separate fields, so the substring check misses them (and could false-positive, e.g. `2.4.49` inside `2.4.490`).

## 5. NVD Week Profiling (Sept 1–7, 2026)

Pulled every CVE published Sept 1–7, 2026 with `scripts/fetch_nvd_window.py` (2 pages: 2,000 + 204). Profiled with `scripts/profile_nvd_window.py`.

| Check | CVEs | % of week |
|---|---|---|
| Total CVEs | 2,204 | 100% |
| Have `configurations` (CPE strings) | 580 | 26% |
| Have `cvssMetricV31` | 1,797 | 82% |
| Have a Primary v3.1 score | 207 | 9% |

`vulnStatus` breakdown:

| Status | CVEs | Have configurations |
|---|---|---|
| Deferred | 1,136 | 0 |
| Analyzed | 537 | 537 |
| Awaiting Analysis | 268 | 0 |
| Received | 188 | 0 |
| Modified | 43 | 43 |
| Rejected | 22 | 0 |
| Undergoing Analysis | 10 | 0 |

Why so low: NVD has an analysis backlog. CPE `configurations` and most Primary scores are only added when an NVD analyst reviews a CVE (Analyzed / Modified). Over half the week is `Deferred`, meaning NVD does not plan to analyze it. Most v3.1 scores are Secondary, from the reporting org (vendor / CNA), not NVD.

Top products by CVE count (only `vulnerable: true` entries, each product counted once per CVE):

| Vendor | Product | CVEs |
|---|---|---|
| arubanetworks | fabric_composer | 52 |
| google | chrome | 38 |
| dell | secure_connect_gateway | 36 |
| hpe | arubaos-cx | 34 |
| mozilla | thunderbird | 31 |
| nvidia | nemo_megatron_bridge | 30 |
| mozilla | firefox | 26 |
| elastic | kibana | 23 |
| ibm | i | 22 |
| misp-project | misp | 20 |

Takeaways:

- Counting every `cpeMatch` entry instead of once per CVE inflates products that list each version separately (Cisco IOS XR: 333 entries from only 3 CVEs × 111 versions). Fix: collect `(vendor, product)` pairs in a **set per CVE**, then add the set to a `Counter`.
- One CVE can affect several products (e.g. Firefox + Thunderbird share code), so total product counts (849) exceed the number of CVEs (580).
- `vulnerable: false` entries are platforms (e.g., Windows for a Chrome bug), not affected products, so they should not count.
- Version is often `*` in the CPE with the real range in `versionEndExcluding` / similar fields. → solved in [section 7](#7-version-range-matcher).
- Synthetic installed software should use real products from this list so matches actually happen. → done in [section 6](#6-generated-synthetic-data).

## 6. Generated Synthetic Data

`scripts/generate_synthetic.py` → `data/raw/synthetic/generated/`

- `random.seed(7)` so every run produces identical files.
- **Assets (500):** device type, OS from `os_by_device`, department, owner from `owners_by_department`, hostname like `server-luffy-007`.
- Realism rules:
  - Internet exposure chance by device: server 40%, VM 25%, laptop / workstation 2%.
  - Criticality weights `[high, medium, low]` by device: server `[60, 30, 10]`, VM `[40, 40, 20]`, laptop `[10, 40, 50]`, workstation `[20, 40, 40]`.
  - Servers and VMs only belong to engineering or IT.
- Owners are team names (not people) because people leave but teams stay, and it keeps the data shareable.
- **Installed software (1,396 rows):** 2–4 server apps per server/VM, 2–3 desktop apps per laptop/workstation, picked with `random.sample` (no duplicates on one machine).
- Software catalog uses real products from profiling. Each product has vulnerable versions plus one patched version, checked against the week's CVE ranges:

| Product | Versions (last = patched) |
|---|---|
| google / chrome | 151.0.7922.100, 152.0.7977.50, 152.0.7977.82 |
| mozilla / firefox | 153.1.0, 154.0.1, 155.0.1 |
| mozilla / thunderbird | 140.14.0, 153.1.0, 155.0.1 |
| elastic / kibana | 8.19.20, 9.4.5, 9.6.0 |
| jenkins / jenkins | 2.568.1, 2.579, 2.580 |
| n8n / n8n | 2.35.3, 2.36.1, 2.37.0 |
| haxx / curl | 8.15.0, 8.21.0, 8.22.0 |
| nodejs / undici | 7.29.0, 8.10.1, 8.10.2 |

Lesson learned: a probability like `random.random() < 0.4` must be rolled **inside** the loop. Putting it in a dict before the loop rolls once, so every server got the same answer.

## 7. Version-Range Matcher

`scripts/match_window.py` replaced the prototype matcher.

- `version_tuple("8.22.0")` → `(8, 22, 0)` so versions compare as numbers. String compare is wrong: `"8.9.0" < "8.22.0"` is `False`.
- `is_version_vulnerable(installed, cpe_match)`:
  - exact version in the CPE → must equal the installed version
  - `*` → start vulnerable, then rule out with each range key that exists

| Key | Not vulnerable if installed is... |
|---|---|
| `versionStartIncluding` | `<` start |
| `versionStartExcluding` | `<=` start |
| `versionEndIncluding` | `>` end |
| `versionEndExcluding` | `>=` end |

- Skips `Rejected` CVEs and CVEs without `configurations`.
- Score: Primary v3.1 if present, else Secondary, recorded as `score_source`. Without the fallback, 14,383 exposures would have had no score.
- `software_by_product` groups software by `(vendor, product)` so each CPE only checks machines that have that product.
- `seen` set prevents duplicate rows when a CVE lists the same product in several `cpeMatch` entries.
- Result: 18,056 exposures across 470 of 500 assets.

## 8. Generated Patch Tickets

`scripts/generate_synthetic_patches.py` → `data/raw/synthetic/generated/patches_records9773.json`

- One ticket per `(asset_id, cve_id)`, not per exposure row. 18,056 exposures → 16,158 unique pairs. All 1,898 repeats were the same CVE hitting **Firefox and Thunderbird** on the same machine.
- ~60% of pairs get a ticket (assumption). No ticket → matcher treats it as `open` (found by the scanner, but nobody has created a ticket yet).
- Status weights `[patched, in_progress, open, accepted_risk]` by urgency. Urgency is computed from severity + internet exposure + criticality, not from the exposure's `priority` field, because `priority` already includes old patch tickets (a `done` row crashed the generator on a rerun).
  - `patch_now`: `[60, 30, 10, 0]` — critical, exposed, important machines are never accepted risk
  - `review`: `[40, 20, 25, 15]`
- `patched_timestamp` only on patched rows; `exception_reason` only on accepted-risk rows (pattern: set both to `None`, then overwrite inside `if`).
- `remediation_owner` comes from the asset's `asset_owner`.
- Result: 9,773 tickets. After joining into the matcher: `patch_now` dropped 76 → 37, and 4,377 exposures became `done`.
- `match_window.py` still runs if the patch file is missing (everything treated as `open`).

## 9. Open Issues / Future Improvements

- **Platform conditions ignored:** CPE AND/OR logic is not evaluated, so a "Chrome on Windows" CVE also matches Chrome on macOS.
- **Letter versions:** `version_tuple` only handles numbers (`1.0.2k` would crash).
- **Coverage:** only 26% of new CVEs have CPE data. Other sources (vendor advisories, description parsing) could fill gaps.
- **Accepted risk priority:** currently shows as `review`; could get its own label so it doesn't clutter the to-do list.
- **Timestamps:** synthetic timestamps are fixed strings; could be randomized within realistic ranges.
- **Next phase:** rebuild the pipeline in PySpark (flatten CVEs → CPE rows, join to software), then Databricks Bronze / Silver / Gold.
