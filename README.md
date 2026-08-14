# CVE_Compass Project README

## Overview

This CVE Compass is an end-to-end Azure data engineering platform that identifies which publicly reported software vulnerabilities affect an organization’s computers, servers, and applications. 

It demonstrates how a data engineer collects, stores, cleans, matches, tests, and delivers complex cybersecurity data through a production-style cloud pipeline. It also solves a realistic business problem by helping security teams decide which vulnerable systems should be patched first instead of treating every published vulnerability equally. For employers, the project provides evidence of Python, advanced SQL, PySpark, Azure, data modeling, incremental processing, data quality, monitoring, CI/CD, and technical documentation skills. Because the company assets and patch records are synthetically generated, the project remains safe, legal, publicly shareable, and suitable for a professional portfolio.

## Personal Documentation

### Aug 14

#### Got a sample snippet of NVD CVE data (10 cve recordings).**

__Useful Paths__


CVE_ID -> vulnerabilities[i].cve.id

Description -> vulnerabilities[i].cve.descriptions[0].value

Severity -> vulnerabilities[i].cve.metrics.cvssMetricV2[0].baseSeverity 

Affected Product -> vulnerabilities[i].cve.configurations[0].nodes[0].cpeMatch[0].criteria

Note: cvssMetricV2 is mostly 1990s. Newer ones are V3 or V4