import random
import json
from collections import Counter
from pathlib import Path

random.seed(71)

#-----Set Up-----
with open("data/processed/exposures_window.json") as ew:
    exposures = json.load(ew)

with open("data/raw/synthetic/generated/assets500.json") as a:
    assets500 = json.load(a)

patch_statuses = ["patched", "in_progress", "open", "accepted_risk"]
status_weights_by_priority = {
    "patch_now": [60, 30, 10, 0],
    "review": [40, 20, 25, 15],
}

exception_reasons = [
    "legacy system, scheduled for replacement",
    "compensating control in place (firewall rule)",
    "vendor patch breaks critical workflow",
    "isolated test environment",
]

assets_by_id = {asset["asset_id"]: asset for asset in assets500}

#-----Patch Matching-----
seen_pairs = set()
unique_exposures = []

for exposure in exposures: #one cve for each asset -> possible to have multiple softwares on one asset
    pair = (exposure["asset_id"], exposure["cve_id"])
    if pair in seen_pairs:
        continue
    seen_pairs.add(pair) 
    unique_exposures.append(exposure) #18056 exposures: 16158 unique asset + CVE pairs

all_patches = []

for exposure in unique_exposures:
    chance = random.random()
    if chance >= 0.6: #keeps 60% of pairs for a patch status, 40% have no patch ticket and are just open
        continue

    # Urgency from the CVE + asset only, not exposure["priority"], which already reflects old patch tickets
    is_urgent = (
        exposure["base_severity"] == "CRITICAL"
        and exposure["internet_exposed"] is True
        and exposure["business_criticality"] == "high"
    )
    urgency = "patch_now" if is_urgent else "review"
    weights = status_weights_by_priority[urgency]
    patch_status = random.choices(patch_statuses, weights=weights)[0]
    asset = assets_by_id[exposure["asset_id"]]

    patched_timestamp = None
    exception_reason = None
    if patch_status == "patched":
        patched_timestamp = "2026-09-15T14:00:00Z"
    if patch_status == "accepted_risk":
        exception_reason = random.choice(exception_reasons)

    patch_dict = {
        "asset_id": exposure["asset_id"],
        "cve_id": exposure["cve_id"],
        "first_detected_timestamp": "2026-09-08T09:00:00Z",
        "patch_available": True,
        "patch_status": patch_status,
        "patched_timestamp": patched_timestamp,
        "remediation_owner": asset["asset_owner"],
        "exception_reason": exception_reason,
    }
    all_patches.append(patch_dict)

OUTPUT_PATH = Path("data/raw/synthetic/generated/patches_records9773.json")
with OUTPUT_PATH.open("w") as f:
    json.dump(all_patches, f, indent=2)

print("patch records:", len(all_patches))
print(Counter(patch["patch_status"] for patch in all_patches))
print("saved:", OUTPUT_PATH)

