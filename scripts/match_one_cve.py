import json

#loading our matched cve
with open("data/raw/nvd/cve-2021-41773.json") as one_cve:
    one_cve_data = json.load(one_cve)

#loading our synthetic installed softwares
with open("data/raw/synthetic/installed_software.json") as syn_cves:
    syn_cves_data = json.load(syn_cves)

#loading our synthetic assets
with open("data/raw/synthetic/assets.json") as assets:
    syn_assets_data = json.load(assets)

#load cve id being used (2021)
one_cve_id = one_cve_data["vulnerabilities"][0]["cve"]["id"] 

#retrieving list of criteria strings (2021)
criteria_list = []
configurations = one_cve_data["vulnerabilities"][0]["cve"]["configurations"]
for configuration in configurations:
    for node in configuration["nodes"]:
        for cpe_match in node["cpeMatch"]:
            criteria_list.append(cpe_match["criteria"])

for software in syn_cves_data:
    for criteria in criteria_list:
        if software["software_vendor"] in criteria and software["software_name"] in criteria and software["installed_version"] in criteria:
            print(software["asset_id"], one_cve_id, software["software_vendor"], software["software_name"], software["installed_version"])
        
    


