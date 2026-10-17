import json

#load window page 0
with open("data/raw/nvd/window_page_0.json") as w:
    window0 = json.load(w)

#load window page 1
with open("data/raw/nvd/window_page_1.json") as p:
    window1 = json.load(p)

all_vulnerabilities = window0["vulnerabilities"] + window1["vulnerabilities"]

#check num config, metricv31, primary types
config_count = 0
metricv31_count = 0
primary_count = 0

for item in all_vulnerabilities:
    cve = item["cve"]
    if "configurations" in cve:
        config_count += 1
    if "cvssMetricV31" in cve["metrics"]:
        metricv31_count += 1
        has_primary = False
        for metricv31 in cve["metrics"]["cvssMetricV31"]:
            if metricv31["type"] == "Primary":
                has_primary = True
        if has_primary:
            primary_count += 1
    
print("Total CVEs:", len(all_vulnerabilities))
print("CVEs with configurations:", config_count)
print("CVEs with cvssMetricV31:", metricv31_count)
print("CVEs with cvssMetricV31 with Primary Type:", primary_count)
