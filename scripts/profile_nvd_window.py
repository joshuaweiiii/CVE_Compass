import json

#load window page 0
with open("data/raw/nvd/window_page_0.json") as w:
    window0 = json.load(w)

#load window page 1
with open("data/raw/nvd/window_page_1.json") as p:
    window1 = json.load(p)

all_vulnerabilities = window0["vulnerabilities"] + window1["vulnerabilities"]

