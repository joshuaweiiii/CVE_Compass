# CVE Compass

**Match real NVD vulnerabilities to a company's machines and rank what to patch first.**

Development notes and learning log: [`docs/dev_notes.md`](docs/dev_notes.md)

## Table of Contents

- [Overview](#overview)
- [Results](#results-current-local-pipeline)
- [Pipeline](#pipeline)
- [Data Model](#data-model)
- [Data Sources](#data-sources)
- [Key Findings and Limitations](#key-findings-and-limitations)
- [How to Run](#how-to-run)
- [Project Structure](#project-structure)
- [Roadmap](#roadmap)

## Overview

CVE Compass is a data engineering project that identifies which publicly reported software vulnerabilities (CVEs) affect an organization's computers, servers, and applications, then prioritizes which ones to fix first.

Security teams receive thousands of new CVEs every week. Most don't affect their machines, and of the ones that do, only a few are truly urgent. CVE Compass pulls real vulnerability data from the National Vulnerability Database (NVD), matches it against a company's software inventory, joins asset and patch information, and ranks each exposure so the team can focus on what matters.

Company data (assets, installed software, patch tickets) is synthetic, so the project is safe, legal, and fully shareable. Vulnerability data is real.

The local Python pipeline is complete. Next phases rebuild it in PySpark, Databricks (Bronze / Silver / Gold), and Azure (see [Roadmap](#roadmap)).

## Results (current local pipeline)

One week of real CVEs (published Sept 1–7, 2026) matched against a synthetic 500-machine company:

| Metric | Value |
|---|---|
| CVEs pulled from NVD | 2,204 |
| CVEs matchable (have CPE product data) | 580 (26%) |
| Synthetic assets / installed software rows | 500 / 1,396 |
| Exposures found (asset + CVE + product) | 18,056 |
| Assets with at least one exposure | 470 of 500 |
| Patch tickets (synthetic) | 9,773 |

Priority breakdown:

| Priority | Exposures | Meaning |
|---|---|---|
| `patch_now` | 37 | Open, CRITICAL severity, internet-exposed, high-criticality asset |
| `review` | 13,642 | Still needs attention, but not urgent |
| `done` | 4,377 | Already patched |

Out of 18,056 exposures, the security team gets a short list of **37** to fix immediately.

## Pipeline

```text
fetch_nvd_window.py ──► profile_nvd_window.py
        │
        ▼
generate_synthetic.py ──► match_window.py ──► generate_synthetic_patches.py ──► match_window.py
(assets + software)        (exposures)          (patch tickets)                  (final exposures
                                                                                   with patch status)
```

| Script | What it does | Output |
|---|---|---|
| `scripts/fetch_nvd_window.py` | Pulls every CVE published in a date window from the NVD API 2.0, paginating 2,000 at a time | `data/raw/nvd/window_page_*.json` |
| `scripts/profile_nvd_window.py` | Profiles the pull: coverage counts and top affected products | printed summary |
| `scripts/generate_synthetic.py` | Generates 500 assets and their installed software (seeded, reproducible) | `data/raw/synthetic/generated/assets500.json`, `installed_software1396.json` |
| `scripts/match_window.py` | Matches CVE products and version ranges to installed software, joins assets and patches (all `open` if no patch file yet), assigns priority | `data/processed/exposures_window.json` |
| `scripts/generate_synthetic_patches.py` | Generates patch tickets for ~60% of asset + CVE pairs, weighted by priority | `data/raw/synthetic/generated/patches_records9773.json` |

## Data Model

```text
┌─────────────┐         cve_id          ┌─────────────────┐
│     NVD     │─────────────────────────│  Patch records  │
│  (CVEs)     │                         │ asset_id+cve_id │
└──────┬──────┘                         └────────┬────────┘
       │                                         │
       │ match on vendor / product               │ asset_id
       │ + version range                         │
       │                                         ▼
┌──────▼──────────────┐                 ┌─────────────────┐
│ Installed software  │──── asset_id ───│     Assets      │
│ asset_id + vendor/  │                 │  (machines)     │
│ product / version   │                 └─────────────────┘
└─────────────────────┘
```

- **NVD → Installed software:** a CVE's `vulnerable: true` CPE entries are matched on vendor + product, then the installed version is checked against the exact version or `versionStart*` / `versionEnd*` range.
- **Installed software → Assets:** `asset_id` adds hostname, device type, business criticality, and internet exposure.
- **Exposure → Patch records:** `(asset_id, cve_id)` adds patch status. No ticket means `open`.

## Data Sources

**NVD CVE API 2.0 (real).** `https://services.nvd.nist.gov/rest/json/cves/2.0`. A free API key raises the rate limit from 5 to 50 requests per 30 seconds. The key is read from the `NVD_API_KEY` environment variable and never committed.

**Synthetic company data (generated).** Seeded with `random.seed`, so every run produces identical files.

- **Assets (500):** device type, OS, department, owner team, business criticality, internet exposure. 
  - Realism rules: servers are more often high criticality and internet-exposed; servers and VMs belong only to engineering or IT.
- **Installed software (1,396 rows):** 2–4 apps per server/VM, 2–3 per laptop/workstation, chosen from real products in the week's CVE data (Chrome, Firefox, Thunderbird, Kibana, Jenkins, n8n, curl, undici). 
  - Realism rules: Each product has vulnerable and patched versions.
- **Patch tickets (9,773):** ~60% of asset + CVE pairs get a ticket (assumption). 
  - Realism rules: Status weights depend on priority; `patch_now` exposures are never `accepted_risk`.

## Key Findings and Limitations

- **Only 26% of new CVEs are matchable.** NVD adds CPE product data only after analyst review; over half the week was `Deferred` (NVD does not plan to analyze it). Unmatched CVEs can't be tied to software by CPE.
- **Most severity scores come from vendors, not NVD.** The matcher uses NVD's Primary CVSS v3.1 score when available and falls back to the vendor/CNA Secondary score, recorded in `score_source`.
- **Products are counted once per CVE.** Some CVEs list every affected version separately (e.g., Cisco IOS XR: 333 entries from only 3 CVEs).
- **Platform conditions are ignored.** A Chrome CVE that only affects Chrome on Windows also matches Chrome on macOS. Handling CPE AND/OR logic is a future improvement.
- **Numeric versions only.** Versions with letters (e.g., OpenSSL `1.0.2k`) are not supported yet.
- **Synthetic percentages are assumptions**, not real-world statistics.

## How to Run

```bash
# 1. Set up
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 2. Add your NVD API key (https://nvd.nist.gov/developers/request-an-api-key)
export NVD_API_KEY="your-key-here"

# 3. Pull and profile one week of CVEs
python scripts/fetch_nvd_window.py
python scripts/profile_nvd_window.py

# 4. Generate synthetic assets and software
python scripts/generate_synthetic.py

# 5. First match (if no patch file exists yet, every exposure is treated as open)
python scripts/match_window.py

# 6. Generate patch tickets from those exposures
python scripts/generate_synthetic_patches.py

# 7. Final match, now joined with patch status
python scripts/match_window.py
```

The generated patch tickets are already committed, so steps 5–6 are optional. Running step 7 alone uses the committed tickets.

## Project Structure

```text
cve_compass/
├── scripts/                     # current pipeline (5 scripts above)
├── data/
│   ├── raw/nvd/                 # NVD pulls (not committed; re-create with fetch script)
│   ├── raw/synthetic/generated/ # generated assets, software, patch tickets
│   └── processed/               # exposures output (not committed)
├── prototype/                   # early versions: first API call, substring matcher, hand-written samples
├── docs/dev_notes.md            # development notes and learning log
└── requirements.txt             # Python dependencies
```

## Roadmap

- [x] Local Python pipeline: NVD pull, profiling, synthetic data, version-range matching, prioritization
- [ ] PySpark: rebuild flattening and joins as DataFrames
- [ ] Databricks: Bronze / Silver / Gold Delta tables
- [ ] Azure: Data Factory ingestion, ADLS storage, Azure SQL serving layer
- [ ] Power BI: exposure and priority dashboard
- [ ] Data quality checks, monitoring, and CI/CD
