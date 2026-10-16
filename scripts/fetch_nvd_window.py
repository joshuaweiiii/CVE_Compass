import json
import os
from pathlib import Path
import requests

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OUTPUT_PATH = Path("data/raw/nvd/window_page_0.json")

api_key = os.environ.get("NVD_API_KEY")

headers = {"apiKey": api_key}
params = {
    "pubStartDate": "2026-09-01T00:00:00.000",
    "pubEndDate": "2026-09-07T23:59:59.999",
    "resultsPerPage": 2000,
    "startIndex": 0,
    }

response = requests.get(API_URL, headers=headers, params=params, timeout=60)
print("status:", response.status_code) #200 good, 403 bad, 429 too much
response.raise_for_status() #raises error and crashes script if there is one

OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
with OUTPUT_PATH.open("w") as f:
    json.dump(response.json(), f, indent=2)

print("saved:", OUTPUT_PATH)