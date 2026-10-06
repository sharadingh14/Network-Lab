"""Stage 1: load, clean, sample, split chronologically and de-duplicate.
Output: data/processed/split.pkl and results/data_summary.json"""
import os
import pickle
import sys

import numpy as np
import pandas as pd
import yaml

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from hbids.data import (chronological_split, describe, feature_columns, load_days,  # noqa: E402
                        remove_cross_split_duplicates, save_summary)


def main(cfg_path="configs/default.yaml"):
    cfg = yaml.safe_load(open(cfg_path))
    rng = np.random.default_rng(cfg["seed_list"][0])
    summary = {}
    df = load_days(cfg, rng, summary)
    feats = feature_columns(df, cfg)
    # Feature vectors that occur with more than one label (a known artefact of this dataset)
    h = pd.util.hash_pandas_object(df[feats], index=False)
    lab_per_vec = df.groupby(h.values)["Label"].nunique()
    conflict = set(lab_per_vec[lab_per_vec > 1].index)
    mask = ~h.isin(conflict).values
    summary["rows_with_conflicting_labels_removed"] = int((~mask).sum())
    summary["conflicting_label_pairs"] = (
        df[~mask].groupby(h.values[~mask])["Label"].agg(lambda s: " | ".join(sorted(set(s))))
        .value_counts().head(10).to_dict())
    df = df[mask]
    df[feats] = df[feats].astype(np.float32)
    split = chronological_split(df, cfg)
    split = remove_cross_split_duplicates(split, feats, summary)
    describe(split, summary)
    summary["n_features_candidate"] = len(feats)
    summary["features_candidate"] = feats
    os.makedirs("data/processed", exist_ok=True)
    with open("data/processed/split.pkl", "wb") as f:
        pickle.dump({"split": split, "feats": feats}, f)
    save_summary(summary)
    print({k: v for k, v in summary.items() if k.endswith("_rows") or k.startswith("rows_")})


if __name__ == "__main__":
    main(*sys.argv[1:])
