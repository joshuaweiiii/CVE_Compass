import json
import os
from pathlib import Path
import requests
import time

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

api_key = os.environ.get("NVD_API_KEY")

start_index = 0
page_number = 0
headers = {"apiKey": api_key}

while True:

    params = {
        "pubStartDate": "2026-09-01T00:00:00.000",
        "pubEndDate": "2026-09-07T23:59:59.999",
        "resultsPerPage": 2000,
        "startIndex": start_index,
        }

    response = requests.get(API_URL, headers=headers, params=params, timeout=60)
    print("status:", response.status_code) #200 good, 403 bad, 429 too much
    response.raise_for_status() #raises error and crashes script if there is one
    data = response.json()

    OUTPUT_PATH = Path(f"data/raw/nvd/window_page_{page_number}.json")

    print("Total Results:", data["totalResults"])
    print("Results Per Page:", data["resultsPerPage"])
    print("Start Index:", data["startIndex"])
    print("Num Vulnerabilities:", len(data["vulnerabilities"]))

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_PATH.open("w") as f:
        json.dump(data, f, indent=2)

    print("saved:", OUTPUT_PATH)

    start_index += len(data["vulnerabilities"]) #start index starts at how many cves came back
    page_number += 1

    if start_index >= data["totalResults"]: #break if totalResults are pulled
        break
    if len(data["vulnerabilities"]) == 0: #break if empty page
        break
    else:
        time.sleep(3)