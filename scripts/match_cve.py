import json
from pathlib import Path

# =========================
# Loading
# =========================

#loading our matched 2021 cve
with open("data/raw/nvd/cve-2021-41773.json") as mc:
    one_cve_data = json.load(mc)

#loading our synthetic installed softwares
with open("data/raw/synthetic/installed_software.json") as sc:
    syn_softwares_data = json.load(sc)

#loading our synthetic assets
with open("data/raw/synthetic/assets.json") as a:
    syn_assets_data = json.load(a)

#loading our synthetic patches
with open("data/raw/synthetic/patches.json") as p:
    syn_patches_data = json.load(p)

#loading our 10 old cves
with open("data/raw/nvd/sample_cves.json") as s:
    sample_cves = json.load(s)

# =========================
# Dict Creation
# =========================

#new dict with asset id as key for entire asset row
assets_by_id = {}
for asset in syn_assets_data:
    assets_by_id[asset["asset_id"]] = asset

#new dict with asset id + cve id as key for entire patch row
patches_by_id = {}
for patch in syn_patches_data:
    patches_by_id[(patch["asset_id"], patch["cve_id"])] = patch

# =========================
# Main
# =========================

exposures = []
all_cves = sample_cves["vulnerabilities"] + one_cve_data["vulnerabilities"]

#look through each individual cve
for item in all_cves: 
    cve = item["cve"] 
    cve_id = cve["id"] #cve id

    #pull score + severity
    if "cvssMetricV31" not in cve["metrics"]:
        continue

    cve_score = None
    for metric in cve["metrics"]["cvssMetricV31"]: 
        if metric["type"] == "Primary":
            cve_score = metric["cvssData"]["baseScore"]
            cve_severity = metric["cvssData"]["baseSeverity"]
    if cve_score is None:
        continue

    #pull criteria strings for current cve
    criteria_list = [] 
    for configuration in cve["configurations"]:
        for node in configuration["nodes"]:
            for cpe_match in node["cpeMatch"]:
                criteria_list.append(cpe_match["criteria"])

    #match current cve criteria strings to synthetic software + assets + patches
    for software in syn_softwares_data: 
        for criteria in criteria_list:
            if software["software_vendor"] in criteria and software["software_name"] in criteria and software["installed_version"] in criteria:
                print(software["asset_id"], cve_id, software["software_vendor"], software["software_name"], software["installed_version"])
                
                asset = assets_by_id[software["asset_id"]]#pull assets
                print(asset["hostname"], asset["business_criticality"], asset["internet_exposed"])

                patch = patches_by_id.get((software["asset_id"], cve_id)) #pull patches
                if patch is None:
                    patch_status = "open"
                else:
                    patch_status = patch["patch_status"]

                if patch_status == "patched":
                    priority = "done"
                elif (
                    patch_status == "open" 
                    and cve_severity == "CRITICAL" 
                    and asset["internet_exposed"] is True 
                    and asset["business_criticality"] == "high"
                ):
                    priority = "patch_now"
                else:
                    priority = "review"

                match_dict = {
                    "asset_id": software["asset_id"],
                    "cve_id": cve_id,
                    "vendor": software["software_vendor"],
                    "product": software["software_name"],
                    "version": software["installed_version"],
                    "hostname": asset["hostname"],
                    "business_criticality": asset["business_criticality"],
                    "internet_exposed": asset["internet_exposed"],
                    "base_score": cve_score,
                    "base_severity": cve_severity,
                    "patch_status": patch_status,
                    "priority": priority
                }
                exposures.append(match_dict)

#writing all cve matches to processed folder
out_path = Path("data/processed/exposures.json")
out_path.parent.mkdir(parents=True, exist_ok=True)
with open(out_path, "w") as f:
    json.dump(exposures, f, indent = 2)

