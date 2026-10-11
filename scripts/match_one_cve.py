import json

#loading our matched cve
with open("data/raw/nvd/cve-2021-41773.json") as one_cve:
    one_cve_data = json.load(one_cve)

# #loading our synthetic installed softwares
# with open("data/raw/synthetic/installed_software.json") as syn_cves:
#     syn_cves_data = json.load(syn_cves)

one_cve_id = one_cve_data["vulnerabilities"][0]["cve"]["id"] #load cve id being used

criteria_list = []

configurations = one_cve_data["vulnerabilities"][0]["cve"]["configurations"]
for configuration in configurations:
    for node in configuration["nodes"]:
        for cpe_match in node["cpeMatch"]:
            criteria_list.append(cpe_match["criteria"])




