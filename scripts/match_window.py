import json
from pathlib import Path

WINDOW_PAGES = [
    "data/raw/nvd/window_page_0.json",
    "data/raw/nvd/window_page_1.json",
]
ASSETS_PATH = "data/raw/synthetic/generated/assets500.json"
SOFTWARE_PATH = "data/raw/synthetic/generated/installed_software1396.json"
PATCHES_PATH = "data/raw/synthetic/generated/patches_records9773.json"

OUTPUT_PATH = Path("data/processed/exposures_window.json")


def version_tuple(version):
    """Turn "8.22.0" into (8, 22, 0) so versions compare as numbers, not text."""
    return tuple(int(part) for part in version.split("."))


def is_version_vulnerable(installed_version, cpe_match):
    """True if installed_version falls inside this cpe_match's vulnerable versions."""
    cpe_version = cpe_match["criteria"].split(":")[5]

    # A specific version in the CPE string means only that exact version is vulnerable
    if cpe_version not in ("*", "-"):
        return installed_version == cpe_version

    installed = version_tuple(installed_version)

    if "versionStartIncluding" in cpe_match:
        if installed < version_tuple(cpe_match["versionStartIncluding"]):
            return False
    if "versionStartExcluding" in cpe_match:
        if installed <= version_tuple(cpe_match["versionStartExcluding"]):
            return False
    if "versionEndIncluding" in cpe_match:
        if installed > version_tuple(cpe_match["versionEndIncluding"]):
            return False
    if "versionEndExcluding" in cpe_match:
        if installed >= version_tuple(cpe_match["versionEndExcluding"]):
            return False

    return True


def get_cvss_v31(cve):
    """Return (score, severity, source_type): Primary (NVD) first, else Secondary (vendor/CNA)."""
    metrics = cve["metrics"].get("cvssMetricV31", [])
    for wanted_type in ["Primary", "Secondary"]:
        for metric in metrics:
            if metric["type"] == wanted_type:
                return (
                    metric["cvssData"]["baseScore"],
                    metric["cvssData"]["baseSeverity"],
                    wanted_type,
                )
    return None, None, None


# ---------- load ----------
all_vulnerabilities = [] #all cves
for page in WINDOW_PAGES:
    with open(page) as f:
        all_vulnerabilities += json.load(f)["vulnerabilities"]

with open(ASSETS_PATH) as f: #all assets
    assets = json.load(f)
with open(SOFTWARE_PATH) as f: #all softwares
    software_rows = json.load(f)
with open(PATCHES_PATH) as f: #all patches
    patches = json.load(f)

assets_by_id = {asset["asset_id"]: asset for asset in assets}

patches_by_id = {}
for patch in patches:
    patches_by_id[(patch["asset_id"], patch["cve_id"])] = patch

# (vendor, product) -> every installed row of that product, so each CPE only checks relevant software
software_by_product = {}
for row in software_rows:
    key = (row["software_vendor"], row["software_name"])
    software_by_product.setdefault(key, []).append(row)

# ---------- match ----------
exposures = []
seen = set()

for item in all_vulnerabilities:
    cve = item["cve"]
    cve_id = cve["id"]

    if cve.get("vulnStatus") == "Rejected":
        continue
    if "configurations" not in cve:
        continue

    score, severity, score_source = get_cvss_v31(cve)

    for configuration in cve["configurations"]:
        for node in configuration["nodes"]:
            for cpe_match in node["cpeMatch"]:
                if not cpe_match["vulnerable"]:
                    continue

                parts = cpe_match["criteria"].split(":")
                vendor, product = parts[3], parts[4]

                for software in software_by_product.get((vendor, product), []):
                    if not is_version_vulnerable(software["installed_version"], cpe_match):
                        continue

                    # One CVE can list the same product in several cpeMatch entries
                    key = (software["asset_id"], cve_id, vendor, product)
                    if key in seen:
                        continue
                    seen.add(key)

                    asset = assets_by_id[software["asset_id"]]
                    patch = patches_by_id.get((software["asset_id"], cve_id)) #pull patches
                    if patch is None:
                        patch_status = "open"
                    else:
                        patch_status = patch["patch_status"]
                    if patch_status == "patched":
                        priority = "done"
                    elif (
                        patch_status == "open"
                        and severity == "CRITICAL"
                        and asset["internet_exposed"] is True
                        and asset["business_criticality"] == "high"
                    ):
                        priority = "patch_now"
                    else:
                        priority = "review"

                    exposures.append({
                        "asset_id": asset["asset_id"],
                        "cve_id": cve_id,
                        "software_vendor": vendor,
                        "software_name": product,
                        "installed_version": software["installed_version"],
                        "hostname": asset["hostname"],
                        "device_type": asset["device_type"],
                        "business_criticality": asset["business_criticality"],
                        "internet_exposed": asset["internet_exposed"],
                        "base_score": score,
                        "base_severity": severity,
                        "score_source": score_source,
                        "patch_status": patch_status,
                        "priority": priority,
                    })

# ---------- save ----------
OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
with OUTPUT_PATH.open("w") as f:
    json.dump(exposures, f, indent=2)

print("exposures found:", len(exposures))
print("assets affected:", len({e["asset_id"] for e in exposures}))
print("patch_now:", sum(1 for e in exposures if e["priority"] == "patch_now"))
print("saved:", OUTPUT_PATH)
