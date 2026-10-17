import json
from collections import Counter

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
product_counts = Counter()

for item in all_vulnerabilities:
    cve = item["cve"]

    if "configurations" in cve:
        config_count += 1
        #Which products had the most CVEs this week?
        cve_products = set() #get vendor + product for each cve
        for configuration in cve["configurations"]:
            for node in configuration["nodes"]:
                for cpe_match in node["cpeMatch"]:
                    if cpe_match["vulnerable"]:
                        criteria_split = cpe_match["criteria"].split(":")
                        cve_products.add((criteria_split[3], criteria_split[4])) #(vendor, product)
        for pair in cve_products:
            product_counts[pair] += 1

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
for pair in product_counts.most_common(20):
    print("Most Common Product Counts:", pair)
