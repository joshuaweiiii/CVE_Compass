import json
import os
from pathlib import Path
import requests

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OUTPUT_PATH = Path("data/raw/nvd/sample_cves.json")

api_key = os.environ.get("NVD_API_KEY")

headers = {"api_key": api_key}
params = {"resultsPerPage": 10}

response = requests.get(API_URL, headers=headers, params=params, timeout=10)
print("status:", response.status_code) #200 good, 403 bad, 429 too much
response.raise_for_status() #raises error and crashes script if there is one

OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
with OUTPUT_PATH.open("w") as f:
    json.dump(response.json(), f, indent=2)

print("saved:", OUTPUT_PATH)