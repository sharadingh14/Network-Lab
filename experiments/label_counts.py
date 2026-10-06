"""Raw per-label record counts of each day file before any cleaning (results/raw_label_counts.json)."""
import json
import os
import sys

import pandas as pd
import yaml

cfg = yaml.safe_load(open(sys.argv[1] if len(sys.argv) > 1 else "configs/default.yaml"))
out = {}
for day in cfg["data"]["days"]:
    s = pd.read_csv(os.path.join(cfg["data"]["raw_dir"], f"{day}.csv"), usecols=["Label"])["Label"]
    out[day] = {k: int(v) for k, v in s[s != "Label"].value_counts().items()}
json.dump(out, open("results/raw_label_counts.json", "w"), indent=1)
print(out)
