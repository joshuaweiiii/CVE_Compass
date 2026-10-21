import random
import json
from pathlib import Path

random.seed(7)

device_types = ["server", "laptop", "workstation", "virtual_machine"]
departments = ["engineering", "finance", "hr", "sales", "marketing", "it"]
criticality_levels = ["high", "medium", "low"]

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

all_assets = []

for i in range(1, 501):
    device = random.choice(device_types)
    operating_system = random.choice(os_by_device[device])
    department = random.choice(departments)
    owner = random.choice(owners_by_department["department"])
    criticality_level = random.choice(criticality_levels)
    internet_exposed = random.random() < 0.3
    asset_id = f"ASSET-:{i:003d}"
    hostname = "hi"
    last_scan_time = "2026-10-01T12:00:00Z"

    asset_dict = {
      "asset_id": asset_id,
      "hostname": "hi",
      "device_type": device,
      "operating_system": operating_system,
      "department": department,
      "business_criticality": criticality_level,
      "internet_exposed": internet_exposed,
      "asset_owner": owner,
      "last_scan_timestamp": last_scan_time
    }
    all_assets.append(all_assets)


