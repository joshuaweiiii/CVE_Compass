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
    os = random.choice(os_by_device["device"])
    department = random.choice(departments)
    owner = random.choice(owners_by_department["department"])
    criticality_level = random.choice(criticality_levels)
    internet_exposed = random.random() < 0.3
    asset_id = f"{i}:003d"
    hostname = "hi"
    last_scan_time = "2026-10-01T12:00:00Z"

    
