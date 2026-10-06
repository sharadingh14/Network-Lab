"""Stage 2: component ablation of the detection pipeline (single pooled site).

Configurations evaluated on the chronologically last 20 % of every (day, label) group:
  signature only | MLP | XGBoost | RandomForest | ensemble (all features) | ensemble (GA features)
  | hybrid = signature then ensemble (all features) | hybrid (GA features)
Output: results/detection.json"""
import json
import os
import pickle
import sys
import time

import numpy as np
import yaml

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from hbids.ga import ga_select  # noqa: E402
from hbids.metrics import binary_metrics, per_family_recall  # noqa: E402
from hbids.models import Ensemble  # noqa: E402
from hbids.signatures import BenignReference, KeySpace, SignatureDB, extract_signatures  # noqa: E402


def build_signature_db(train, ks, cfg, origin="central"):
    kh, ka = ks.keys(train)
    att = train["y"].values == 1
    cands = extract_signatures(kh, ka, att, ks.fields, cfg["signatures"]["min_support"], origin)
    ref = BenignReference(kh[~att])
    tol = cfg["signatures"]["validator_benign_tolerance"]
    kept = [s for s in cands if ref.match_fraction(s) <= tol]
    db = SignatureDB()
    db.add(kept)
    return db, len(cands), len(kept)


def main(cfg_path="configs/default.yaml"):
    cfg = yaml.safe_load(open(cfg_path))
    d = pickle.load(open("data/processed/split.pkl", "rb"))
    sp, feats = d["split"], d["feats"]
    tr, ev = sp.train, sp.eval
    Xtr, ytr = tr[feats].values, tr["y"].values
    Xev, yev, fam = ev[feats].values, ev["y"].values, ev["Family"].values
    ks = KeySpace(cfg["signatures"]["key_fields"], cfg["signatures"]["max_bin"])
    db, n_cand, n_kept = build_signature_db(tr, ks, cfg)
    kh_ev, _ = ks.keys(ev)
    t0 = time.perf_counter(); sig_pred = db.match(kh_ev).astype(np.int8); t_sig = time.perf_counter() - t0
    out = {"n_eval": int(len(ev)), "n_train": int(len(tr)), "signature_candidates": n_cand,
           "signatures_kept": n_kept, "runs": []}
    for seed in cfg["seed_list"]:
        run = {"seed": seed, "results": {}, "per_family": {}}
        ga_log = []
        t0 = time.perf_counter()
        grp = (tr["Day"].astype(str) + "|" + tr["Label"].astype(str)).values
        mask = ga_select(Xtr, ytr, tr["Timestamp"].values.astype("int64"), cfg, seed, ga_log, groups=grp)
        run["ga_time_s"] = time.perf_counter() - t0
        run["ga_log"] = ga_log
        run["ga_selected"] = [f for f, m in zip(feats, mask) if m]
        for tag, cols in (("all", np.ones(len(feats), bool)), ("ga", mask)):
            ens = Ensemble(cfg, seed)
            t0 = time.perf_counter(); ens.fit(Xtr[:, cols], ytr); run[f"train_time_{tag}_s"] = time.perf_counter() - t0
            t0 = time.perf_counter(); probs = ens.member_proba(Xev[:, cols]); t_inf = time.perf_counter() - t0
            run[f"inference_us_per_flow_{tag}"] = 1e6 * t_inf / len(Xev)
            pred, score = ens.predict(Xev, probs), ens.score(Xev, probs)
            for name, p in probs.items():
                run["results"][f"{name}_{tag}"] = binary_metrics(yev, (p >= 0.5).astype(int), p)
            if tag == "ga":
                run["results"]["signature_only"] = binary_metrics(yev, sig_pred, sig_pred.astype(float))
                run["per_family"]["signature_only"] = per_family_recall(fam, yev, sig_pred)
            run["results"][f"ensemble_{tag}"] = binary_metrics(yev, pred, score)
            run["per_family"][f"ensemble_{tag}"] = per_family_recall(fam, yev, pred)
            hyb = np.maximum(sig_pred, pred)
            hscore = np.maximum(sig_pred.astype(float), score)
            run["results"][f"hybrid_{tag}"] = binary_metrics(yev, hyb, hscore)
            run["per_family"][f"hybrid_{tag}"] = per_family_recall(fam, yev, hyb)
            if True:
                from sklearn.metrics import precision_recall_curve, roc_curve
                fpr, tpr, _ = roc_curve(yev, hscore)
                pr, rc, _ = precision_recall_curve(yev, hscore)
                idx = np.linspace(0, len(fpr) - 1, min(400, len(fpr))).astype(int)
                idx2 = np.linspace(0, len(pr) - 1, min(400, len(pr))).astype(int)
                run[f"curves_{tag}"] = {"fpr": fpr[idx].tolist(), "tpr": tpr[idx].tolist(),
                                 "precision": pr[idx2].tolist(), "recall": rc[idx2].tolist()}
        run["signature_match_us_per_flow"] = 1e6 * t_sig / len(ev)
        out["runs"].append(run)
        print(seed, {k: round(v["f1"], 4) for k, v in run["results"].items()}, flush=True)
        json.dump(out, open("results/detection.json", "w"), indent=1)


if __name__ == "__main__":
    main(*sys.argv[1:])
