import json

#check assets
with open("data/raw/synthetic/assets.json") as assets:
    data = json.load(assets)

#check how many assets
print("assets:", len(data)) 

#grab unique asset ids
total_asset_ids = {row["asset_id"] for row in data} 


#check softwares
with open("data/raw/synthetic/installed_software.json") as software:
    data = json.load(software)

#check how many softwares
print("softwares:", len(data))

#check if software asset IDs match the total asset IDs
for row in data:
    if row["asset_id"] not in total_asset_ids:
        print("Warning! Software ID is not in total IDs: ", row["asset_id"])


#check patches
with open("data/raw/synthetic/patches.json") as patches:
    data = json.load(patches)

#check how many patches
print("patches:", len(data))

#check if patch asset IDs match the total asset IDs
for row in data:
    if row["asset_id"] not in total_asset_ids:
        print("Warning! Patch ID is not in total IDs: ", row["asset_id"])

