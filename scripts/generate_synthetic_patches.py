import random
import json

random.seed(71)

with open("data/processed/exposures_window.json") as ew:
    exposures = json.load(ew)

with open("data/raw/synthetic/generated/assets500.json") as a:
    assets500 = json.load(a)

seen_pairs = set()
unique_pairs = []

for exposure in exposures: #one cve for each asset -> possible to have multiple softwares on one asset
    pair = (exposure["asset_id"], exposure["cve_id"])
    if pair in seen_pairs:
        continue
    seen_pairs.add(pair) 
    unique_pairs.append(exposure) #18056 exposures: 16158 unique asset + CVE pairs
