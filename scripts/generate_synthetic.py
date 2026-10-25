import random
import json
from collections import Counter
from pathlib import Path


random.seed(7)

device_types = ["server", "laptop", "workstation", "virtual_machine"]
departments = ["engineering", "finance", "hr", "sales", "marketing", "it"]
technical_departments = ["engineering", "it"]
criticality_levels = ["high", "medium", "low"]
hostname_names = [
    "naruto", "sasuke", "kakashi", "itachi",
    "luffy", "zoro", "sanji", "nami", "gojo", "itadori",
    "megumi", "tanjiro", "nezuko", "levi", "eren", "mikasa",
    "light", "ryuk", "gon", "killua", "saitama", "genos",
    "deku", "bakugo", "todoroki", "bernie", "josh", "jamie", "justin",
    "matthew", "ethan", "darren", "hailey", "sophia", "eve", "serena", "michelle"
    ]

owners_by_department = {
    "engineering": ["platform-team", "backend-team", "frontend-team", "data-team"],
    "finance": ["finance-ops", "accounting-team"],
    "hr": ["people-ops"],
    "sales": ["sales-ops", "revenue-team"],
    "marketing": ["marketing-ops", "growth-team"],
    "it": ["it-helpdesk", "infra-team", "security-team"],
}
os_by_device = {
    "server": ["ubuntu", "rhel", "debian", "windows_server"],
    "virtual_machine": ["ubuntu", "rhel", "debian", "windows_server"],
    "laptop": ["windows", "macos", "ubuntu"],
    "workstation": ["windows", "macos", "ubuntu"]
}
internet_exposed_by_device = {
    "server": 0.4,
    "virtual_machine": 0.25,
    "laptop": 0.02,
    "workstation": 0.02
}
criticality_level_by_device = {
    "server": [60, 30, 10],
    "virtual_machine": [40, 40, 20],
    "laptop": [10, 40, 50],
    "workstation": [20, 40, 40]
}

# (vendor, product, versions) — last version in each list is patched; the rest are vulnerable
desktop_software = [
    ("google", "chrome", ["151.0.7922.100", "152.0.7977.50", "152.0.7977.82"]),
    ("mozilla", "firefox", ["153.1.0", "154.0.1", "155.0.1"]),
    ("mozilla", "thunderbird", ["140.14.0", "153.1.0", "155.0.1"]),
]
server_software = [
    ("elastic", "kibana", ["8.19.20", "9.4.5", "9.6.0"]),
    ("jenkins", "jenkins", ["2.568.1", "2.579", "2.580"]),
    ("n8n", "n8n", ["2.35.3", "2.36.1", "2.37.0"]),
    ("haxx", "curl", ["8.15.0", "8.21.0", "8.22.0"]),
    ("nodejs", "undici", ["7.29.0", "8.10.1", "8.10.2"]),
]
apps_per_device = {
    "server": (2, 4),
    "virtual_machine": (2, 4),
    "laptop": (2, 3),
    "workstation": (2, 3),
}

all_assets = []
    #generating assets
for i in range(1, 501):
    device = random.choice(device_types)
    operating_system = random.choice(os_by_device[device])
    if device in ["server", "virtual_machine"]:
        department = random.choice(technical_departments)
    else:
        department = random.choice(departments)
    owner = random.choice(owners_by_department[department])
    criticality_level = random.choices(criticality_levels, weights=criticality_level_by_device[device])[0]
    internet_exposed = random.random() < internet_exposed_by_device[device]
    asset_id = f"ASSET-{i:03d}"
    hostname = f"{device}-{random.choice(hostname_names)}-{i:03d}"
    last_scan_time = "2026-10-01T12:00:00Z"

    asset_dict = {
      "asset_id": asset_id,
      "hostname": hostname,
      "device_type": device,
      "operating_system": operating_system,
      "department": department,
      "business_criticality": criticality_level,
      "internet_exposed": internet_exposed,
      "asset_owner": owner,
      "last_scan_timestamp": last_scan_time
    }
    all_assets.append(asset_dict)

    #generating software
    all_software = []

    for asset in all_assets:
        device = asset["device_type"]
        if device in ["server", "virtual_machine"]:
            catalog = server_software
        else:
            catalog = desktop_software

        min_apps, max_apps = apps_per_device[device]
        how_many = random.randint(min_apps, max_apps) #how many products for one asset
        picked = random.sample(catalog, how_many)

        for vendor, product, versions in picked:
            software_dict = {
                "asset_id": asset["asset_id"],
                "software_vendor": vendor,
                "software_name": product,
                "installed_version": random.choice(versions),
                "last_observed_timestamp": asset["last_scan_timestamp"],
            }
            all_software.append(software_dict)


OUTPUT_PATH = Path("data/raw/synthetic/generated/assets500.json")
OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
with OUTPUT_PATH.open("w") as f:
    json.dump(all_assets, f, indent=2)

print("assets generated:", len(all_assets))
print("saved:", OUTPUT_PATH)

SOFTWARE_PATH = Path("data/raw/synthetic/generated/installed_software1396.json")
with SOFTWARE_PATH.open("w") as f:
    json.dump(all_software, f, indent=2)

print("software rows generated:", len(all_software))
print("saved:", SOFTWARE_PATH)

