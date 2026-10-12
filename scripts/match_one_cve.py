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
    syn_cves_data = json.load(sc)

#loading our synthetic assets
with open("data/raw/synthetic/assets.json") as a:
    syn_assets_data = json.load(a)

#loading our synthetic patches
with open("data/raw/synthetic/patches.json") as p:
    syn_patches_data = json.load(p)

#load cve id being used (2021 CVE)
one_cve_id = one_cve_data["vulnerabilities"][0]["cve"]["id"] 

#load score + severity (2021 CVE)
cve_score = one_cve_data["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"] 
cve_severity = one_cve_data["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseSeverity"] 

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

#retrieve list of criteria strings (2021 CVE)
criteria_list = [] 
configurations = one_cve_data["vulnerabilities"][0]["cve"]["configurations"]
for configuration in configurations:
    for node in configuration["nodes"]:
        for cpe_match in node["cpeMatch"]:
            criteria_list.append(cpe_match["criteria"])

#matching 2021 CVE to synthetic softwares + synthetic assets + synthetic patches and creating dict
exposures = []

for software in syn_cves_data:
    for criteria in criteria_list:
        if software["software_vendor"] in criteria and software["software_name"] in criteria and software["installed_version"] in criteria:
            print(software["asset_id"], one_cve_id, software["software_vendor"], software["software_name"], software["installed_version"])
            
            asset = assets_by_id[software["asset_id"]]
            print(asset["hostname"], asset["business_criticality"], asset["internet_exposed"])

            print(patches_by_id[(software["asset_id"], one_cve_id)]["patch_status"])

            match_dict = {
                "asset_id": software["asset_id"],
                "cve_id": one_cve_id,
                "vendor": software["software_vendor"],
                "product": software["software_name"],
                "version": software["installed_version"],
                "hostname": asset["hostname"],
                "business_criticality": asset["business_criticality"],
                "internet_exposed": asset["internet_exposed"],
                "base_score": cve_score,
                "base_severity": cve_severity,
                "patch_status": patches_by_id[(software["asset_id"], one_cve_id)]["patch_status"]
            }

            exposures.append(match_dict)

#writing all cve matches to processed folder
out_path = Path("data/processed/exposures.json")
out_path.parent.mkdir(parents=True, exist_ok=True)
with open(out_path, "w") as f:
    json.dump(exposures, f, indent = 2)

            