"""Phase-1 signatures.

A signature is a discretised flow pattern:
    key = (Protocol, Dst Port, bin(f1), ..., bin(fk))
where f1..fk are fixed flow counters (configs/default.yaml, signatures.key_fields)
and bin(x) = floor(log2(1 + x)). The key space is published in the genesis block,
so a key means the same thing on every node.

Signature JSON format (the payload of a ledger transaction):
    {"sig_id": sha256(key)[:16], "key": [...], "fields": [...], "support": int,
     "origin": node_id, "created": unix_time}
"""
from __future__ import annotations

import hashlib
import json
import time

import numpy as np
import pandas as pd


def key_hash(arr: np.ndarray) -> np.ndarray:
    """Deterministic 64-bit polynomial hash of integer key rows (identical on every node and process)."""
    arr = np.atleast_2d(np.asarray(arr, dtype=np.int64))
    h = np.zeros(arr.shape[0], dtype=np.int64)
    with np.errstate(over="ignore"):
        for j in range(arr.shape[1]):
            h = h * np.int64(1000003) + arr[:, j] + np.int64(7919)
    return h


class KeySpace:
    """Fixed, data-independent key space: Protocol, Dst Port and log2 bins of selected flow counters.

    Because the bins are fixed (bin = floor(log2(1 + x)), capped at max_bin), every node
    computes identical keys without sharing any traffic, and no information from evaluation
    data can leak into the signature definition.
    """
    def __init__(self, fields: list[str], max_bin: int = 24):
        self.fields = fields
        self.max_bin = max_bin

    def keys(self, df: pd.DataFrame):
        cols = [df["Protocol"].astype(np.int64).values, df["Dst Port"].astype(np.int64).values]
        for f in self.fields:
            v = np.clip(df[f].values.astype(np.float64), 0, None)
            cols.append(np.minimum(np.floor(np.log2(1.0 + v)), self.max_bin).astype(np.int64))
        arr = np.stack(cols, axis=1).astype(np.int64)
        return key_hash(arr), arr

    def to_json(self) -> dict:
        return {"fields": ["Protocol", "Dst Port"] + self.fields, "binning": f"floor(log2(1+x)), cap {self.max_bin}"}


def make_signature(key_tuple: np.ndarray, fields: list[str], support: int, origin: str) -> dict:
    k = [int(x) for x in key_tuple]
    return {"sig_id": hashlib.sha256(json.dumps(k).encode()).hexdigest()[:16], "key": k,
            "fields": ["Protocol", "Dst Port"] + fields, "support": int(support),
            "origin": origin, "created": time.time()}


def sig_hash(sig: dict) -> int:
    return int(key_hash(np.array(sig["key"], dtype=np.int64))[0])


def extract_signatures(kh: np.ndarray, key_arr: np.ndarray, flagged: np.ndarray,
                       fields: list[str], min_support: int, origin: str) -> list[dict]:
    """Emit one signature for every key that occurs in at least min_support flagged flows."""
    if flagged.sum() == 0:
        return []
    h = kh[flagged.astype(bool)]
    a = key_arr[flagged.astype(bool)]
    uniq, idx, cnt = np.unique(h, return_index=True, return_counts=True)
    return [make_signature(a[i], fields, c, origin) for u, i, c in zip(uniq, idx, cnt) if c >= min_support]


class SignatureDB:
    def __init__(self):
        self.hashes: set[int] = set()
        self.sigs: dict[str, dict] = {}

    def add(self, sigs: list[dict]):
        for s in sigs:
            self.sigs[s["sig_id"]] = s
            self.hashes.add(sig_hash(s))

    def match(self, kh: np.ndarray) -> np.ndarray:
        if not self.hashes:
            return np.zeros(len(kh), dtype=bool)
        return np.isin(kh, np.fromiter(self.hashes, dtype=np.int64))


class BenignReference:
    """A validator's local benign traffic, summarised as key counts (raw flows never leave the node)."""
    def __init__(self, kh: np.ndarray):
        u, c = np.unique(kh, return_counts=True)
        self.counts = dict(zip(u.tolist(), c.tolist()))
        self.total = int(len(kh))

    def match_fraction(self, sig: dict) -> float:
        return self.counts.get(sig_hash(sig), 0) / max(self.total, 1)
