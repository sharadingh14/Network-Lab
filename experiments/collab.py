"""Stage 3: collaborative detection across sites, with and without signature sharing,
under honest and poisoning conditions, and with Byzantine validators.

Each capture day is treated as one IDS site (node). Node j:
  * trains its ensemble only on its own training traffic,
  * builds signatures from its own training attacks and from flows its detector flags in its
    signature window (initiator self-check against its own benign traffic),
  * is evaluated on its own benign eval traffic plus the eval attacks of ALL sites
    (attacks first seen elsewhere reach it later).
Sharing modes: isolated | authenticated pub-sub (no validation) | permissioned ledger (endorse-order-commit).
Output: results/collab.json"""
import json
import os
import pickle
import sys

import numpy as np
import pandas as pd
import yaml

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from hbids.ledger.cluster import LedgerCluster, PubSub  # noqa: E402
from hbids.metrics import binary_metrics, per_family_recall  # noqa: E402
from hbids.models import Ensemble  # noqa: E402
from hbids.signatures import (BenignReference, KeySpace, SignatureDB, extract_signatures,  # noqa: E402
                              make_signature)


def chunks(x, n):
    for i in range(0, len(x), n):
        yield x[i:i + n]


def ledger_commit(sigs_by_origin, refs, cfg, behaviours, base_port, policy="quorum"):
    n = len(behaviours)
    c = LedgerCluster(n, list(sigs_by_origin), refs, cfg["signatures"]["validator_benign_tolerance"],
                      cfg["signatures"]["min_support"], behaviours=behaviours, base_port=base_port, policy=policy)
    txs = [c.make_tx(o, s) for o, ss in sigs_by_origin.items() for s in ss]
    committed, lat = set(), []
    for b in chunks(txs, cfg["ledger"]["batch_size"]):
        r = c.submit(b, endorse_timeout=1.0)
        committed |= r["committed"]
        lat.append(r["latency_all_s"])
    stats = c.shutdown()
    return committed, lat, stats


def main(cfg_path="configs/default.yaml"):
    cfg = yaml.safe_load(open(cfg_path))
    d = pickle.load(open("data/processed/split.pkl", "rb"))
    sp, feats = d["split"], d["feats"]
    days = cfg["data"]["days"]
    ks = KeySpace(cfg["signatures"]["key_fields"], cfg["signatures"]["max_bin"])
    tol, ms = cfg["signatures"]["validator_benign_tolerance"], cfg["signatures"]["min_support"]
    ev_att = sp.eval[sp.eval["y"] == 1]
    out = {"days": days, "seeds": []}
    malicious = days[0]
    for seed in cfg["seed_list"]:
        nodes, refs, published, poison = {}, [], {}, []
        for day in days:
            tr = sp.train[sp.train["Day"] == day]
            sw = sp.sigwin[sp.sigwin["Day"] == day]
            kh_tr, ka_tr = ks.keys(tr)
            att = tr["y"].values == 1
            ref = BenignReference(kh_tr[~att])
            refs.append(ref)
            s_train = extract_signatures(kh_tr, ka_tr, att, ks.fields, ms, f"ids_{day}")
            ens = Ensemble(cfg, seed).fit(tr[feats].values, tr["y"].values)
            kh_sw, ka_sw = ks.keys(sw)
            db0 = SignatureDB(); db0.add(s_train)
            flagged = (ens.predict(sw[feats].values) == 1) & ~db0.match(kh_sw)
            s_new = extract_signatures(kh_sw, ka_sw, flagged, ks.fields, ms, f"ids_{day}")
            own = [s for s in s_train + s_new if ref.match_fraction(s) <= tol]
            sw_true = sw["y"].values[flagged]
            nodes[day] = {"ens": ens, "own": own, "ref": ref,
                          "train_families": sorted(tr.loc[att, "Family"].unique().tolist()),
                          "sigwin_flagged": int(flagged.sum()),
                          "sigwin_flagged_true_attack_frac": float(sw_true.mean()) if len(sw_true) else None,
                          "n_sig_train": len(s_train), "n_sig_sigwin": len(s_new), "n_sig_published": len(own)}
            published[f"ids_{day}"] = own
            if day == malicious:
                # Poisoning: the malicious node turns its most frequent benign keys into fake signatures.
                bk, ba = kh_tr[~att], ka_tr[~att]
                u, i, c = np.unique(bk, return_index=True, return_counts=True)
                top = np.argsort(c)[::-1][: cfg["poisoning"]["n_poison_signatures"]]
                poison = [make_signature(ba[i[t]], ks.fields, max(int(c[t]), ms), f"ids_{day}") for t in top]
        # ---- sharing via pub-sub and ledger, honest and poisoned ----
        all_pub = [s for ss in published.values() for s in ss]
        pois_pub = {k: (v + poison if k == f"ids_{malicious}" else v) for k, v in published.items()}
        n_val = len(days)
        led_honest, lat_h, st_h = ledger_commit(published, refs, cfg, ["honest"] * n_val, cfg["ledger"]["base_port"])
        led_pois, lat_p, st_p = ledger_commit(pois_pub, refs, cfg, ["honest"] * n_val, cfg["ledger"]["base_port"] + 100)
        led_s_honest, _, _ = ledger_commit(published, refs, cfg, ["honest"] * n_val, cfg["ledger"]["base_port"] + 150, "strict")
        led_s_pois, _, _ = ledger_commit(pois_pub, refs, cfg, ["honest"] * n_val, cfg["ledger"]["base_port"] + 180, "strict")
        ps = PubSub(n_val, list(pois_pub))
        acc = set()
        for o, ss in pois_pub.items():
            for b in chunks([ps.make_tx(o, s) for s in ss], cfg["ledger"]["batch_size"]):
                acc |= ps.publish(b)["accepted"]
        ps.shutdown()
        sid = {s["sig_id"]: s for s in all_pub + poison}
        poison_ids = {s["sig_id"] for s in poison}
        honest_ids = {s["sig_id"] for s in all_pub}
        res = {"seed": seed, "nodes": {}, "ledger": {
            "honest_published": len(honest_ids), "honest_committed_no_attack": len(led_honest & honest_ids),
            "poison_published": len(poison_ids), "poison_committed": len(led_pois & poison_ids),
            "honest_committed_under_attack": len(led_pois & honest_ids),
            "pubsub_poison_accepted": len(acc & poison_ids),
            "strict_honest_committed_no_attack": len(led_s_honest & honest_ids),
            "strict_poison_committed": len(led_s_pois & poison_ids),
            "strict_honest_committed_under_attack": len(led_s_pois & honest_ids),
            "block_latency_s_mean": float(np.mean(lat_h)), "validator_stats": st_h}}
        modes = {
            "isolated": None,
            "pubsub": [sid[i] for i in honest_ids],
            "ledger": [sid[i] for i in led_honest],
            "pubsub_poisoned": [sid[i] for i in acc],
            "ledger_poisoned": [sid[i] for i in led_pois],
            "strict": [sid[i] for i in led_s_honest],
            "strict_poisoned": [sid[i] for i in led_s_pois],
        }
        for day in days:
            nd = nodes[day]
            ev_b = sp.eval[(sp.eval["Day"] == day) & (sp.eval["y"] == 0)]
            E = pd.concat([ev_b, ev_att])
            kh_e, _ = ks.keys(E)
            ens_pred = nd["ens"].predict(E[feats].values)
            ens_score = nd["ens"].score(E[feats].values)
            y, fam = E["y"].values, E["Family"].values
            foreign = (y == 1) & ~np.isin(fam, nd["train_families"])
            r = {k: nd[k] for k in ("train_families", "sigwin_flagged", "sigwin_flagged_true_attack_frac",
                                    "n_sig_train", "n_sig_sigwin", "n_sig_published")}
            r["n_eval"], r["n_foreign_attack"] = int(len(E)), int(foreign.sum())
            for mode, shared in modes.items():
                if mode.endswith("poisoned") and day == malicious:
                    continue
                db = SignatureDB(); db.add(nd["own"])
                if shared:
                    db.add(shared)
                pred = np.maximum(db.match(kh_e).astype(np.int8), ens_pred)
                score = np.maximum(db.match(kh_e).astype(float), ens_score)
                m = binary_metrics(y, pred, score)
                m["foreign_recall"] = float(pred[foreign].mean()) if foreign.any() else None
                m["per_family"] = per_family_recall(fam, y, pred)
                r[mode] = m
            res["nodes"][day] = r
            print(seed, day, {m: round(r[m]["f1"], 4) for m in modes if m in r},
                  {m: round(r[m]["FAR"], 5) for m in modes if m in r}, flush=True)
        out["seeds"].append(res)
        json.dump(out, open("results/collab.json", "w"), indent=1, default=str)

    # ---- Byzantine-validator and crash sweeps for both admission policies (last seed's signatures) ----
    sweep, crash = [], []
    for pi, policy in enumerate(("quorum", "strict")):
        for k in range(0, n_val + 1):
            beh = ["malicious"] * k + ["honest"] * (n_val - k)
            led, _, _ = ledger_commit(pois_pub, refs, cfg, beh, cfg["ledger"]["base_port"] + 200 + 300 * pi + 10 * k, policy)
            sweep.append({"policy": policy, "malicious_validators": k, "poison_committed": len(led & poison_ids),
                          "honest_committed": len(led & honest_ids)})
            print("malicious", sweep[-1], flush=True)
        for k in range(0, 3):
            beh = ["honest"] + ["crash"] * k + ["honest"] * (n_val - 1 - k)
            led, lat, _ = ledger_commit(published, refs, cfg, beh, cfg["ledger"]["base_port"] + 400 + 300 * pi + 10 * k, policy)
            crash.append({"policy": policy, "crashed_validators": k, "honest_committed": len(led & honest_ids),
                          "block_latency_s_mean": float(np.nanmean(lat)) if len(lat) else None})
            print("crash", crash[-1], flush=True)
    out["byzantine_sweep"] = sweep
    out["crash_sweep"] = crash
    out["n_validators"] = n_val
    out["malicious_node"] = malicious
    json.dump(out, open("results/collab.json", "w"), indent=1, default=str)


if __name__ == "__main__":
    main(*sys.argv[1:])
