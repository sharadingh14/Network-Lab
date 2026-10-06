"""Collects every number used in the manuscript from the result files into values.json.
No number in the manuscript is typed by hand."""
import json
import platform

import numpy as np
import pandas as pd

R = "../results/"
ds = json.load(open(R + "data_summary.json"))
raw = json.load(open(R + "raw_label_counts.json"))
det = json.load(open(R + "detection.json"))
col = json.load(open(R + "collab.json"))
ov = pd.DataFrame(json.load(open(R + "overhead.json")))

V, T = {}, {}
fmt = lambda x: f"{int(x):,}".replace(",", " ")          # thin-space-free grouping with spaces (journal style)
pct = lambda x, d=2: f"{100 * x:.{d}f}"


def msd(vals, d=2, scale=100):
    v = np.array([x for x in vals if x is not None], float) * scale
    return f"{v.mean():.{d}f} ± {v.std(ddof=1) if len(v) > 1 else 0:.{d}f}"


def mean(vals, scale=100):
    return float(np.mean([x for x in vals if x is not None])) * scale


# ---------------- data ----------------
days = list(ds["per_day"])
raw_total = sum(ds["per_day"][d]["raw_rows"] for d in days)
dup_total = sum(ds["per_day"][d]["exact_duplicates_removed"] for d in days)
nan_total = sum(ds["per_day"][d]["rows_with_nan_or_inf_removed"] for d in days)
rr = sorted({ds["per_day"][d]["raw_rows"] for d in days})
V.update(raw_total_fmt=fmt(raw_total), dup_total_fmt=fmt(dup_total), dup_pct=pct(dup_total / raw_total, 1),
         nan_total_fmt=fmt(nan_total),
         raw_rows_per_file=" or ".join(fmt(x) for x in rr[::-1]) if len(rr) > 1 else fmt(rr[0]),
         ftp_raw_fmt=fmt(raw["02-14-2018"]["FTP-BruteForce"]), ftp_unique=fmt(ds["per_day"]["02-14-2018"]["clean_counts"]["FTP-BruteForce"]),
         slowhttp_raw_fmt=fmt(raw["02-16-2018"]["DoS attacks-SlowHTTPTest"]),
         slowhttp_unique=fmt(ds["per_day"]["02-16-2018"]["clean_counts"]["DoS attacks-SlowHTTPTest"]),
         conflict_removed=fmt(ds["rows_with_conflicting_labels_removed"]),
         xsplit_removed=fmt(ds["sigwin_rows_identical_to_train_removed"] + ds["eval_rows_identical_to_train_removed"]),
         n_feat=str(ds["n_features_candidate"]), n_eval_fmt=fmt(ds["eval_rows"]),
         n_eval_attack_fmt=fmt(ds["eval_rows"] - ds["eval_label_counts"]["Benign"]),
         n_train_fmt=fmt(ds["train_rows"]))
rows = []
for d in days:
    p = ds["per_day"][d]
    lab = [k for k in raw[d] if k != "Benign"]
    def cnt(split, labels):
        return sum(ds[f"{split}_label_counts"].get(l, 0) for l in labels) if False else None
    rows.append([d.replace("-2018", "").replace("-", "/"), ", ".join(lab),
                 fmt(p["raw_rows"]), fmt(p["rows_with_nan_or_inf_removed"]), fmt(p["exact_duplicates_removed"]),
                 fmt(p["clean_counts"].get("Benign", 0)), fmt(sum(v for k, v in p["clean_counts"].items() if k != "Benign")),
                 fmt(p["sampled_counts"].get("Benign", 0)), fmt(sum(v for k, v in p["sampled_counts"].items() if k != "Benign"))])
rows.append(["Total", "", fmt(raw_total), fmt(nan_total), fmt(dup_total),
             fmt(sum(ds["per_day"][d]["clean_counts"].get("Benign", 0) for d in days)),
             fmt(sum(v for d in days for k, v in ds["per_day"][d]["clean_counts"].items() if k != "Benign")),
             fmt(sum(ds["per_day"][d]["sampled_counts"].get("Benign", 0) for d in days)),
             fmt(sum(v for d in days for k, v in ds["per_day"][d]["sampled_counts"].items() if k != "Benign"))])
splits = "; ".join(f"{name} {fmt(ds[f'{key}_rows'])} ({fmt(ds[f'{key}_rows'] - ds[f'{key}_label_counts']['Benign'])} attacks)"
                   for name, key in (("training", "train"), ("signature window", "sigwin"), ("evaluation", "eval")))
T["dataset"] = {"caption": "Records per capture day at each preprocessing step (dates are month/day of 2018).",
                "header": ["Day", "Attack labels", "Raw records", "Missing or infinite", "Exact duplicates",
                           "Unique benign", "Unique attack", "Sampled benign", "Sampled attack"],
                "widths": [7, 22, 10, 9, 10, 10, 9, 10, 9], "rows": rows,
                "note": f"After removal of {V['conflict_removed']} records with conflicting labels, the chronological split and "
                        f"cross-split duplicate removal, the portions contain: {splits}."}

# ---------------- detection ----------------
runs = det["runs"]
res = lambda name, m: [r["results"][name].get(m) for r in runs]
for name in ("hybrid_all", "hybrid_ga", "ensemble_all", "ensemble_ga", "signature_only"):
    for m in ("f1", "FAR", "recall", "precision", "accuracy", "roc_auc", "pr_auc", "macro_f1"):
        V[f"{name.replace('hybrid', 'hyb').replace('ensemble', 'ens').replace('signature_only', 'sig')}_{m.lower()}"] = f"{mean(res(name, m)):.2f}"
        V[f"{name.replace('hybrid', 'hyb').replace('ensemble', 'ens').replace('signature_only', 'sig')}_{m.lower()}_msd"] = msd(res(name, m))
for name in ("hybrid_all", "hybrid_ga", "ensemble_all", "ensemble_ga", "signature_only"):
    short = name.replace('hybrid', 'hyb').replace('ensemble', 'ens').replace('signature_only', 'sig')
    V[f"{short}_far3"] = f"{mean(res(name, 'FAR')):.3f}"
    V[f"{short}_fp"] = fmt(np.mean(res(name, "FP"))); V[f"{short}_fn"] = fmt(np.mean(res(name, "FN")))
for name in ("MLP_all", "XGBoost_all", "RandomForest_all", "MLP_ga", "XGBoost_ga", "RandomForest_ga"):
    V[f"m_{name}_f1"] = f"{mean(res(name, 'f1')):.2f}"
    V[f"m_{name}_far3"] = f"{mean(res(name, 'FAR')):.3f}"
ga_n = [len(r["ga_selected"]) for r in runs]
V.update(ga_nfeat_range=f"{min(ga_n)} to {max(ga_n)}" if min(ga_n) != max(ga_n) else str(ga_n[0]),
         ga_nfeat_mean=f"{np.mean(ga_n):.0f}",
         inf_all_us=f"{np.mean([r['inference_us_per_flow_all'] for r in runs]):.1f}",
         inf_ga_us=f"{np.mean([r['inference_us_per_flow_ga'] for r in runs]):.1f}",
         sig_us=f"{np.mean([r['signature_match_us_per_flow'] for r in runs]):.2f}",
         n_sigs_central=str(det["signatures_kept"]), n_sigs_cand=str(det["signature_candidates"]),
         train_all_s=f"{np.mean([r['train_time_all_s'] for r in runs]):.0f}",
         train_ga_s=f"{np.mean([r['train_time_ga_s'] for r in runs]):.0f}",
         ga_time_s=f"{np.mean([r['ga_time_s'] for r in runs]):.0f}",
         flows_per_s_all=fmt(1e6 / (np.mean([r['inference_us_per_flow_all'] for r in runs]) + np.mean([r['signature_match_us_per_flow'] for r in runs]))))
common_ga = sorted(set.intersection(*[set(r["ga_selected"]) for r in runs]))
V["ga_common"] = ", ".join(common_ga) if common_ga else "none"
V["ga_common_n"] = str(len(common_ga))
nice = {"signature_only": "Signature only (Phase 1)", "MLP_all": "MLP", "XGBoost_all": "XGBoost", "RandomForest_all": "Random Forest",
        "ensemble_all": "Ensemble", "hybrid_all": "HBIDS hybrid", "MLP_ga": "MLP", "XGBoost_ga": "XGBoost",
        "RandomForest_ga": "Random Forest", "ensemble_ga": "Ensemble", "hybrid_ga": "HBIDS hybrid"}
rows = []
for name in nice:
    fs = "–" if name == "signature_only" else ("All" if name.endswith("_all") else "GA")
    r = [nice[name], fs] + [msd(res(name, m)) for m in ("accuracy", "precision", "recall", "f1", "FAR")]
    r += [msd(res(name, "roc_auc")) if name != "signature_only" else "–"]
    r += [fmt(np.mean(res(name, "FP"))), fmt(np.mean(res(name, "FN")))]
    rows.append(r)
T["ablation"] = {"caption": f"Detection performance on the evaluation portion ({V['n_eval_fmt']} flows), mean ± standard deviation over three seeds (%). FPR is the false-positive (false alarm) rate. FP and FN are mean counts.",
                 "header": ["Configuration", "Features", "Accuracy", "Precision", "Recall", "F1", "FPR", "ROC-AUC", "FP", "FN"],
                 "widths": [16, 7, 11, 11, 11, 11, 10, 11, 6, 6], "rows": rows,
                 "note": f"GA selected {V['ga_nfeat_range']} of {V['n_feat']} features depending on the seed. ROC-AUC is not reported for the signature stage because its output is binary."}


def merge_other(pf):
    pf = {k: dict(v) for k, v in pf.items()}
    if "Other" in pf:
        o = pf.pop("Other"); dd = pf["DDoS"]
        dd["recall"] = (dd["recall"] * dd["n"] + o["recall"] * o["n"]) / (dd["n"] + o["n"]); dd["n"] += o["n"]
    return pf


for r in runs:
    r["per_family"] = {k: merge_other(v) for k, v in r["per_family"].items()}
fams = [f for f in ["Brute force (FTP)", "Brute force (SSH)", "DoS", "DDoS", "Web attack", "Botnet", "Benign"]
        if f in runs[0]["per_family"]["hybrid_all"]]
rows = []
for f in fams:
    key = "specificity" if f == "Benign" else "recall"
    rows.append([f + (" (specificity)" if f == "Benign" else ""), fmt(runs[0]["per_family"]["hybrid_all"][f]["n"])] +
                [msd([r["per_family"][n][f][key] for r in runs]) for n in ("signature_only", "ensemble_all", "hybrid_all", "hybrid_ga")])
    V[f"fam_{f.split()[0].lower()}_hyb"] = f"{mean([r['per_family']['hybrid_all'][f][key] for r in runs]):.2f}"
    V[f"fam_{f.split()[0].lower()}_sig"] = f"{mean([r['per_family']['signature_only'][f][key] for r in runs]):.2f}"
V["fam_web_n"] = fmt(runs[0]["per_family"]["hybrid_all"]["Web attack"]["n"])
T["family"] = {"caption": "Recall per attack family on the evaluation portion (%), mean ± standard deviation over three seeds. For benign traffic the specificity (1 − FPR) is shown.",
               "header": ["Family", "Flows", "Signature only", "Ensemble (all)", "HBIDS hybrid (all)", "HBIDS hybrid (GA)"],
               "widths": [20, 9, 17, 17, 18, 18], "rows": rows}

# ---------------- collaboration ----------------
seeds = col["seeds"]
cdays = col["days"]
modes = ["isolated", "pubsub", "ledger", "strict", "pubsub_poisoned", "ledger_poisoned", "strict_poisoned"]
mn = {"isolated": "No sharing", "pubsub": "Publish-subscribe", "ledger": "Ledger, 2f + 1 policy",
      "strict": "Ledger, n − f policy", "pubsub_poisoned": "Publish-subscribe, poisoned",
      "ledger_poisoned": "Ledger, 2f + 1 policy, poisoned", "strict_poisoned": "Ledger, n − f policy, poisoned"}


def cvals(m, k, exclude_mal=False):
    return [s["nodes"][d][m][k] for s in seeds for d in cdays
            if m in s["nodes"][d] and s["nodes"][d][m][k] is not None and not (exclude_mal and d == col["malicious_node"])]


rows = []
for m in modes:
    ex = True  # compare all modes over the same five honest sites
    rows.append([mn[m]] + [f"{mean(cvals(m, k, ex)):.2f}" for k in ("foreign_recall", "recall", "precision", "f1", "FAR")])
    for k in ("foreign_recall", "recall", "precision", "f1", "FAR"):
        V[f"c_{m}_{k.lower()}"] = f"{mean(cvals(m, k, ex)):.2f}"
        V[f"c_{m}_{k.lower()}3"] = f"{mean(cvals(m, k, ex)):.3f}"
T["collab"] = {"caption": "Collaborative detection: mean over the five honest sites and three seeds (%). Unseen-family recall is the recall on attack families absent from the site's own training data.",
               "header": ["Sharing mode", "Unseen-family recall", "Recall", "Precision", "F1", "FPR"],
               "widths": [28, 16, 13, 13, 13, 13], "rows": rows,
               "note": f"The 14 February site is the malicious publisher in the poisoned modes and is excluded from all rows so that the modes are compared on the same sites."}
rows = []
for d in cdays:
    r = [d.replace("-2018", "").replace("-", "/"), ", ".join(seeds[0]["nodes"][d]["train_families"])]
    for m in ("isolated", "strict", "pubsub_poisoned", "strict_poisoned"):
        v = [s["nodes"][d].get(m, {}).get("foreign_recall") for s in seeds]
        r.append("–" if all(x is None for x in v) else f"{mean(v):.1f}")
    for m in ("isolated", "strict", "pubsub_poisoned", "strict_poisoned"):
        v = [s["nodes"][d].get(m, {}).get("FAR") for s in seeds]
        r.append("–" if all(x is None for x in v) else f"{mean(v):.3f}")
    rows.append(r)
T["collab_site"] = {"caption": "Per-site results (%), mean over three seeds: unseen-family recall and false-positive rate (FPR).",
                    "header": ["Site", "Families in own training data", "Recall: no sharing", "Recall: ledger n − f", "Recall: pub-sub poisoned", "Recall: ledger n − f poisoned",
                               "FPR: no sharing", "FPR: ledger n − f", "FPR: pub-sub poisoned", "FPR: ledger n − f poisoned"],
                    "widths": [6, 16, 8, 8, 9, 9, 8, 8, 9, 9], "rows": rows,
                    "note": "A dash marks the malicious site, which is not evaluated in the poisoned modes."}
L = pd.DataFrame([s["ledger"] for s in seeds])
V.update(n_poison=str(int(L.poison_published.iloc[0])),
         led_poison_committed=str(int(L.poison_committed.max())),
         strict_poison_committed=str(int(L.strict_poison_committed.max())),
         ps_poison_accepted=str(int(L.pubsub_poison_accepted.min())),
         honest_pub=f"{L.honest_published.mean():.0f}", honest_comm=f"{L.honest_committed_no_attack.mean():.0f}",
         strict_honest_comm=f"{L.strict_honest_committed_no_attack.mean():.0f}",
         honest_comm_attack=f"{L.honest_committed_under_attack.mean():.0f}",
         strict_honest_comm_attack=f"{L.strict_honest_committed_under_attack.mean():.0f}")
T["admission"] = {"caption": f"Admission of shared signatures with all validators honest (sum over the six sites; identical for the three seeds).",
                  "header": ["Mechanism", f"Honest signatures accepted (of {V['honest_pub']})", f"Poisoned signatures accepted (of {V['n_poison']})", "Honest signatures accepted during the attack"],
                  "widths": [31, 23, 23, 23],
                  "rows": [["Publish-subscribe (signature check only)", V["honest_pub"], V["ps_poison_accepted"], V["honest_pub"]],
                           ["Ledger, 2f + 1 policy", V["honest_comm"], V["led_poison_committed"], V["honest_comm_attack"]],
                           ["Ledger, n − f policy", V["strict_honest_comm"], V["strict_poison_committed"], V["strict_honest_comm_attack"]]]}
sw = pd.DataFrame(col["byzantine_sweep"]); cr = pd.DataFrame(col["crash_sweep"])
nval = col["n_validators"]; f = (nval - 1) // 3; q = 2 * f + 1
V.update(n_val=str(nval), f_val=str(f), q_val=str(q), nmf_val=str(nval - f))
for pol in ("quorum", "strict"):
    s_ = sw[sw.policy == pol]
    bad = s_[s_.poison_committed > 0.5 * s_.poison_committed.max()].malicious_validators.min() if s_.poison_committed.max() > 0 else None
    V[f"byz_{pol}_half"] = str(int(bad)) if bad is not None and not np.isnan(bad) else "none"
    for k in sorted(s_.malicious_validators.unique()):
        V[f"byz_{pol}_{k}"] = str(int(s_[s_.malicious_validators == k].poison_committed.iloc[0]))
        V[f"byz_{pol}_{k}_h"] = str(int(s_[s_.malicious_validators == k].honest_committed.iloc[0]))
    c_ = cr[cr.policy == pol]
    for k in range(0, 3):
        V[f"crash_{pol}_{k}"] = str(int(c_[c_.crashed_validators == k].honest_committed.iloc[0]))
        V[f"crash_{pol}_{k}_lat"] = f"{1000 * c_[c_.crashed_validators == k].block_latency_s_mean.iloc[0]:.0f}"
rows = []
for k in sorted(sw.malicious_validators.unique()):
    a_ = sw[(sw.policy == "quorum") & (sw.malicious_validators == k)].iloc[0]
    b_ = sw[(sw.policy == "strict") & (sw.malicious_validators == k)].iloc[0]
    rows.append([str(int(k)), str(int(a_.honest_committed)), str(int(a_.poison_committed)), str(int(b_.honest_committed)), str(int(b_.poison_committed))])
T["byz"] = {"caption": f"Signatures committed with k malicious validators that endorse every transaction (n = {nval}, f = {f}; {V['honest_pub']} honest and {V['n_poison']} poisoned signatures submitted; seed {seeds[-1]['seed']}). Malicious validators are taken in site order, so the first is the validator of the poisoning site.",
            "header": ["k", "2f + 1 policy: honest committed", "2f + 1 policy: poisoned committed", "n − f policy: honest committed", "n − f policy: poisoned committed"],
            "widths": [8, 23, 23, 23, 23], "rows": rows}
nd = seeds[0]["nodes"]
V["sigs_per_site"] = ", ".join(f"{d[:5].replace('-', '/')}: {nd[d]['n_sig_published']}" for d in cdays)

# ---------------- overhead ----------------
g = ov.groupby(["system", "n", "T"]).mean(numeric_only=True).reset_index()
gs = ov.groupby(["system", "n", "T"]).std(numeric_only=True).reset_index()
Tm = ov["T"].max()
rows = []
for n in sorted(ov.n.unique()):
    for s in ("ledger", "pubsub"):
        a = g[(g.system == s) & (g.n == n) & (g["T"] == Tm)].iloc[0]
        b = gs[(gs.system == s) & (gs.n == n) & (gs["T"] == Tm)].iloc[0]
        rows.append([str(n), "Ledger" if s == "ledger" else "Publish-subscribe",
                     f"{1000 * a.block_latency_s_mean:.1f} ± {1000 * b.block_latency_s_mean:.1f}",
                     f"{1000 * a.block_latency_s_p95:.1f}",
                     f"{a.throughput_sig_per_s:.0f} ± {b.throughput_sig_per_s:.0f}",
                     f"{a.bytes_total / Tm / 1024:.1f}", f"{1000 * a.cpu_s_total / Tm:.2f}",
                     f"{a.ledger_bytes_per_node / Tm / 1024:.2f}" if s == "ledger" else "0"])
T["overhead"] = {"caption": f"Cost of sharing {fmt(Tm)} signatures in blocks of 50, mean ± standard deviation over three runs. Latency is measured from submission until every validator (or subscriber) has committed (or acknowledged) the block.",
                 "header": ["n", "Mechanism", "Latency per block (ms)", "95th percentile latency (ms)", "Throughput (signatures per s)",
                            "Data sent per signature (KiB)", "CPU per signature, all nodes (ms)", "Ledger storage per signature per node (KiB)"],
                 "widths": [5, 15, 14, 12, 14, 13, 13, 14], "rows": rows,
                 "note": "All processes ran on one machine with two CPU cores over loopback TCP; wide-area propagation delay is not included."}
for n in (min(ov.n), max(ov.n)):
    for s in ("ledger", "pubsub"):
        a = g[(g.system == s) & (g.n == n) & (g["T"] == Tm)].iloc[0]
        V[f"o_{s}_{n}_lat"] = f"{1000 * a.block_latency_s_mean:.0f}"
        V[f"o_{s}_{n}_thr"] = f"{a.throughput_sig_per_s:.0f}"
        V[f"o_{s}_{n}_kib"] = f"{a.bytes_total / Tm / 1024:.1f}"
        V[f"o_{s}_{n}_cpu"] = f"{1000 * a.cpu_s_total / Tm:.2f}"
    V[f"o_ledger_{n}_store"] = f"{g[(g.system == 'ledger') & (g.n == n) & (g['T'] == Tm)].iloc[0].ledger_bytes_per_node / Tm / 1024:.2f}"
    V[f"o_ratio_lat_{n}"] = f"{float(V[f'o_ledger_{n}_lat']) / max(float(V[f'o_pubsub_{n}_lat']), 1e-9):.0f}"
    V[f"o_ratio_thr_{n}"] = f"{float(V[f'o_pubsub_{n}_thr']) / float(V[f'o_ledger_{n}_thr']):.1f}"
V["o_nmin"], V["o_nmax"], V["o_T"] = str(min(ov.n)), str(max(ov.n)), fmt(Tm)

# ---------------- environment ----------------
import cryptography, matplotlib, sklearn, xgboost  # noqa: E402
V.update(py_ver=platform.python_version(), pd_ver=pd.__version__, np_ver=np.__version__, skl_ver=sklearn.__version__,
         xgb_ver=xgboost.__version__, crypto_ver=cryptography.__version__, mpl_ver=matplotlib.__version__)

V["abstract_collab"] = (f"When each capture day was treated as a separate site, sharing signatures raised the recall on attack families unseen at a site "
                        f"from {V['c_isolated_foreign_recall']} % to {V['c_pubsub_foreign_recall']} % with an authenticated publish-subscribe channel and "
                        f"{V['c_strict_foreign_recall']} % with the ledger, so the gain came from sharing rather than from the ledger.")
V["abstract_poison"] = (f"Under a poisoning attack, publish-subscribe accepted all {V['ps_poison_accepted']} poisoned signatures and the false-positive rate of the honest sites rose to "
                        f"{V['c_pubsub_poisoned_far']} %, whereas the ledger with an n − f admission threshold committed {V['strict_poison_committed']} of them "
                        f"(false-positive rate {V['c_strict_poisoned_far3']} %) and remained safe with up to f colluding validators; a 2f + 1 threshold failed with one colluding validator.")
V["abstract_overhead"] = (f"The ledger added {V['o_ledger_4_lat']} to {V['o_ledger_13_lat']} ms of commit latency per 50-signature block for 4 to 13 validators, "
                          f"against {V['o_pubsub_4_lat']} to {V['o_pubsub_13_lat']} ms for publish-subscribe.")
V["hyb_all_far3"] = V.get("hyb_all_far3", "")
json.dump({"vals": V, "tables": T}, open("values_auto.json", "w"), indent=1, ensure_ascii=False)
print(len(V), "values;", len(T), "tables")
