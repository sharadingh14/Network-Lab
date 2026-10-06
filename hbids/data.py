"""Loading, cleaning and chronological splitting of CSE-CIC-IDS2018 day files.

Every count produced here is written to results/data_summary.json so that the
paper reports exactly what was used.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass

import numpy as np
import pandas as pd

FAMILY = {
    "Benign": "Benign",
    "FTP-BruteForce": "Brute force (FTP)",
    "SSH-Bruteforce": "Brute force (SSH)",
    "DoS attacks-GoldenEye": "DoS",
    "DoS attacks-Slowloris": "DoS",
    "DoS attacks-SlowHTTPTest": "DoS",
    "DoS attacks-Hulk": "DoS",
    "DDoS attack-LOIC-UDP": "DDoS",
    "DDOS attack-HOIC": "DDoS",
    "DDOS attack-LOIC-HTTP": "DDoS",
    "DDOS attack-LOIC-UDP": "DDoS",
    "DDoS attacks-LOIC-HTTP": "DDoS",
    "Brute Force -Web": "Web attack",
    "Brute Force -XSS": "Web attack",
    "SQL Injection": "Web attack",
    "Bot": "Botnet",
    "Infilteration": "Infiltration",
}


@dataclass
class Split:
    train: pd.DataFrame
    sigwin: pd.DataFrame
    eval: pd.DataFrame


def _read_day(path: str) -> pd.DataFrame:
    df = pd.read_csv(path, low_memory=False)
    df.columns = [c.strip() for c in df.columns]
    # Some Kaggle day files repeat the header row inside the data.
    df = df[df["Label"].astype(str) != "Label"]
    return df


def load_days(cfg: dict, rng: np.random.Generator, summary: dict) -> pd.DataFrame:
    dcfg = cfg["data"]
    frames = []
    summary["per_day"] = {}
    for day in dcfg["days"]:
        path = os.path.join(dcfg["raw_dir"], f"{day}.csv")
        df = _read_day(path)
        raw_rows = len(df)
        ts = pd.to_datetime(df["Timestamp"], format="%d/%m/%Y %H:%M:%S", errors="coerce")
        if ts.isna().mean() > 0.5:   # fall back if a mirror uses another timestamp layout
            ts = pd.to_datetime(df["Timestamp"], format="mixed", dayfirst=True, errors="coerce")
        df["Timestamp"] = ts
        df = df.dropna(subset=["Timestamp"])
        for c in df.columns:
            if c not in ("Timestamp", "Label") and df[c].dtype == object:
                df[c] = pd.to_numeric(df[c], errors="coerce")
        feat_cols = [c for c in df.columns if c not in ("Timestamp", "Label")]
        df[feat_cols] = df[feat_cols].replace([np.inf, -np.inf], np.nan)
        n_nan = int(df[feat_cols].isna().any(axis=1).sum())
        df = df.dropna(subset=feat_cols)
        n_before_dup = len(df)
        df = df.drop_duplicates(subset=[c for c in feat_cols if c not in dcfg["drop_columns"]] + ["Label"])
        n_dup = n_before_dup - len(df)
        counts_clean = df["Label"].value_counts().to_dict()
        parts = []
        for label, g in df.groupby("Label"):
            cap = dcfg["max_benign_per_day"] if label == "Benign" else dcfg["max_attack_per_label"]
            if len(g) > cap:
                g = g.iloc[np.sort(rng.choice(len(g), cap, replace=False))]
            parts.append(g)
        df = pd.concat(parts)
        df["Day"] = day
        summary["per_day"][day] = {
            "raw_rows": raw_rows,
            "rows_with_nan_or_inf_removed": n_nan,
            "exact_duplicates_removed": n_dup,
            "clean_counts": {k: int(v) for k, v in counts_clean.items()},
            "sampled_counts": {k: int(v) for k, v in df["Label"].value_counts().items()},
        }
        frames.append(df)
    df = pd.concat(frames, ignore_index=True)
    df = df[df["Label"] != "Infilteration"]
    df["Family"] = df["Label"].map(FAMILY).fillna("Other")
    df["y"] = (df["Label"] != "Benign").astype(np.int8)
    return df


def chronological_split(df: pd.DataFrame, cfg: dict) -> Split:
    """Split every (day, label) group in time order: oldest -> train, middle -> signature window, newest -> eval."""
    fr = cfg["data"]["split"]
    tr, sw, ev = [], [], []
    for _, g in df.groupby(["Day", "Label"], sort=False):
        g = g.sort_values("Timestamp", kind="stable")
        n = len(g)
        a = int(round(n * fr["train"]))
        b = int(round(n * (fr["train"] + fr["signature_window"])))
        tr.append(g.iloc[:a]); sw.append(g.iloc[a:b]); ev.append(g.iloc[b:])
    return Split(pd.concat(tr), pd.concat(sw), pd.concat(ev))


def feature_columns(df: pd.DataFrame, cfg: dict) -> list[str]:
    skip = set(cfg["data"]["drop_columns"]) | set(cfg["data"]["exclude_from_ml"]) | {"Label", "Family", "y", "Day", "Timestamp"}
    cols = [c for c in df.columns if c not in skip]
    # Remove constant columns (several flag and bulk-rate columns are always zero in this dataset).
    return [c for c in cols if df[c].nunique() > 1]


def remove_cross_split_duplicates(split: Split, feats: list[str], summary: dict) -> Split:
    """Drop signature-window and eval rows whose feature vector already occurs in train."""
    train_keys = set(pd.util.hash_pandas_object(split.train[feats], index=False).values)
    out = {}
    for name in ("sigwin", "eval"):
        d = getattr(split, name)
        h = pd.util.hash_pandas_object(d[feats], index=False).values
        mask = np.array([k not in train_keys for k in h])
        summary[f"{name}_rows_identical_to_train_removed"] = int((~mask).sum())
        out[name] = d[mask]
    return Split(split.train, out["sigwin"], out["eval"])


def describe(split: Split, summary: dict) -> None:
    for name in ("train", "sigwin", "eval"):
        d = getattr(split, name)
        summary[f"{name}_label_counts"] = {k: int(v) for k, v in d["Label"].value_counts().items()}
        summary[f"{name}_rows"] = int(len(d))


def save_summary(summary: dict, path: str = "results/data_summary.json") -> None:
    with open(path, "w") as f:
        json.dump(summary, f, indent=2, default=str)
