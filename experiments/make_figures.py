"""Stage 5: figures (PNG, 300 dpi) and tables (CSV) from results/*.json. Nothing is typed by hand."""
import json
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

plt.rcParams.update({"font.size": 9, "font.family": "DejaVu Sans", "axes.spines.top": False,
                     "axes.spines.right": False, "savefig.dpi": 300, "savefig.bbox": "tight"})
C = {"ledger": "#1f77b4", "pubsub": "#ff7f0e", "isolated": "#7f7f7f"}
os.makedirs("figures", exist_ok=True)
os.makedirs("results/tables", exist_ok=True)


def ms(vals):
    v = np.array([x for x in vals if x is not None], dtype=float)
    return v.mean(), (v.std(ddof=1) if len(v) > 1 else 0.0)


def detection():
    d = json.load(open("results/detection.json"))
    names = ["signature_only", "MLP_all", "XGBoost_all", "RandomForest_all", "ensemble_all", "hybrid_all",
             "MLP_ga", "XGBoost_ga", "RandomForest_ga", "ensemble_ga", "hybrid_ga"]
    nice = {"signature_only": "Signature only (Phase 1)", "MLP_all": "MLP, all features", "XGBoost_all": "XGBoost, all features",
            "RandomForest_all": "Random Forest, all features", "MLP_ga": "MLP, GA features", "XGBoost_ga": "XGBoost, GA features",
            "RandomForest_ga": "Random Forest, GA features", "ensemble_all": "Ensemble, all features",
            "ensemble_ga": "Ensemble, GA features", "hybrid_all": "HBIDS hybrid, all features",
            "hybrid_ga": "HBIDS hybrid, GA features"}
    metrics = ["accuracy", "precision", "recall", "f1", "macro_f1", "FAR", "roc_auc", "pr_auc"]
    rows = []
    for n in names:
        row = {"Configuration": nice[n]}
        for m in metrics:
            mu, sd = ms([r["results"][n].get(m) for r in d["runs"]])
            row[m] = f"{100*mu:.2f} ± {100*sd:.2f}"
        cm = {k: int(np.mean([r["results"][n][k] for r in d["runs"]])) for k in ("TP", "FP", "TN", "FN")}
        row.update(cm)
        rows.append(row)
    pd.DataFrame(rows).to_csv("results/tables/table_detection_ablation.csv", index=False)
    # per-family recall ("Other" in early runs = LOIC-UDP, which belongs to DDoS; merged n-weighted)
    def fam_table(pf):
        pf = {k: dict(v) for k, v in pf.items()}
        if "Other" in pf:
            o = pf.pop("Other"); dd = pf["DDoS"]
            dd["recall"] = (dd["recall"] * dd["n"] + o["recall"] * o["n"]) / (dd["n"] + o["n"]); dd["n"] += o["n"]
        return pf
    for r in d["runs"]:
        r["per_family"] = {k: fam_table(v) for k, v in r["per_family"].items()}
    fams = sorted(d["runs"][0]["per_family"]["hybrid_all"].keys())
    rows = []
    for f in fams:
        row = {"Family": f, "n": d["runs"][0]["per_family"]["hybrid_all"][f]["n"]}
        for n in ("signature_only", "ensemble_all", "hybrid_all", "hybrid_ga"):
            key = "specificity" if f == "Benign" else "recall"
            mu, sd = ms([r["per_family"][n][f][key] for r in d["runs"]])
            row[nice[n]] = f"{100*mu:.2f} ± {100*sd:.2f}"
        rows.append(row)
    pd.DataFrame(rows).to_csv("results/tables/table_per_family.csv", index=False)
    # GA convergence + ROC/PR
    fig, ax = plt.subplots(1, 3, figsize=(10.5, 3))
    for r in d["runs"]:
        g = pd.DataFrame(r["ga_log"])
        ax[0].plot(g["generation"], g["best"], label=f"seed {r['seed']}")
    ax[0].set_xlabel("Generation"); ax[0].set_ylabel("Best fitness"); ax[0].set_title("(a) GA convergence"); ax[0].legend(frameon=False)
    for tag, col, lab in (("all", C["ledger"], "All features"), ("ga", C["pubsub"], "GA features")):
        r0 = d["runs"][0][f"curves_{tag}"]
        ax[1].plot(r0["fpr"], r0["tpr"], color=col, label=lab)
        ax[2].plot(r0["recall"], r0["precision"], color=col, label=lab)
    ax[1].set_xlabel("False-positive rate (log scale)"); ax[1].set_ylabel("True-positive rate"); ax[1].set_title("(b) ROC, HBIDS hybrid")
    ax[1].set_xscale("log"); ax[1].set_xlim(1e-5, 1); ax[1].legend(frameon=False, loc="lower right")
    ax[2].set_xlabel("Recall"); ax[2].set_ylabel("Precision"); ax[2].set_title("(c) Precision-recall, HBIDS hybrid")
    ax[2].set_ylim(0.9, 1.001)
    fig.savefig("figures/fig_ga_roc_pr.png"); plt.close(fig)
    # confusion matrix
    r = d["runs"][0]["results"]["hybrid_all"]
    cm = np.array([[r["TN"], r["FP"]], [r["FN"], r["TP"]]])
    fig, ax = plt.subplots(figsize=(3, 2.6))
    ax.imshow(cm, cmap="Blues")
    for i in range(2):
        for j in range(2):
            ax.text(j, i, f"{cm[i, j]:,}", ha="center", va="center", color="white" if cm[i, j] > cm.max() / 2 else "black")
    ax.set_xticks([0, 1], ["Benign", "Attack"]); ax.set_yticks([0, 1], ["Benign", "Attack"])
    ax.set_xlabel("Predicted"); ax.set_ylabel("Actual"); ax.set_title(f"HBIDS hybrid, all features (seed {d['runs'][0]['seed']})")
    fig.savefig("figures/fig_confusion.png"); plt.close(fig)


def collab():
    d = json.load(open("results/collab.json"))
    modes = ["isolated", "pubsub", "ledger", "strict", "pubsub_poisoned", "ledger_poisoned", "strict_poisoned"]
    nice = {"isolated": "No sharing", "pubsub": "Publish-subscribe", "ledger": "Ledger, 2f+1 policy",
            "strict": "Ledger, n-f policy", "pubsub_poisoned": "Publish-subscribe, poisoned",
            "ledger_poisoned": "Ledger 2f+1, poisoned", "strict_poisoned": "Ledger n-f, poisoned"}
    mal = d["malicious_node"]
    honest_days = [x for x in d["days"] if x != mal]
    agg = []
    for m in modes:
        r = {"Mode": nice[m]}
        for k in ("foreign_recall", "recall", "precision", "f1", "FAR"):
            vals = [s["nodes"][day][m][k] for s in d["seeds"] for day in honest_days if s["nodes"][day][m][k] is not None]
            r[k] = f"{100*np.mean(vals):.3f}"
        agg.append(r)
    pd.DataFrame(agg).to_csv("results/tables/table_collab_summary.csv", index=False)
    led = pd.DataFrame([s["ledger"] for s in d["seeds"]]).drop(columns=["validator_stats"])
    led.to_csv("results/tables/table_ledger_admission.csv", index=False)
    fig, ax = plt.subplots(1, 2, figsize=(9, 3.4))
    x = np.arange(len(honest_days))
    show = ["isolated", "pubsub", "ledger", "strict", "pubsub_poisoned", "ledger_poisoned", "strict_poisoned"]
    cols = {"isolated": "#9e9e9e", "pubsub": "#fdbf6f", "ledger": "#a6cee3", "strict": "#b2df8a",
            "pubsub_poisoned": "#ff7f00", "ledger_poisoned": "#1f78b4", "strict_poisoned": "#33a02c"}
    w = 0.12
    for i, m in enumerate(show):
        fr = [np.mean([s["nodes"][day][m]["foreign_recall"] for s in d["seeds"]]) for day in honest_days]
        fa = [np.mean([s["nodes"][day][m]["FAR"] for s in d["seeds"]]) for day in honest_days]
        ax[0].bar(x + (i - 3) * w, 100 * np.array(fr), w, label=nice[m], color=cols[m])
        ax[1].bar(x + (i - 3) * w, 100 * np.array(fa), w, color=cols[m])
    ax[0].set_title("(a) Recall on attack families unseen locally (%)"); ax[1].set_title("(b) False-positive rate (%), log scale")
    ax[1].set_yscale("log"); ax[1].set_ylim(0.01, 100)
    for a_ in ax:
        a_.set_xticks(x, [s_[:5].replace("-", "/") for s_ in honest_days]); a_.set_xlabel("Site (capture day, 2018)")
    fig.tight_layout(rect=(0, 0.14, 1, 1))
    fig.legend(*ax[0].get_legend_handles_labels(), loc="lower center", ncol=4, frameon=False, bbox_to_anchor=(0.5, 0.0), fontsize=8)
    fig.savefig("figures/fig_collab.png"); plt.close(fig)
    sw = pd.DataFrame(d["byzantine_sweep"])
    sw.to_csv("results/tables/table_byzantine_sweep.csv", index=False)
    pd.DataFrame(d["crash_sweep"]).to_csv("results/tables/table_crash_sweep.csv", index=False)
    n = d["n_validators"]
    fig, ax = plt.subplots(figsize=(4.6, 3))
    for pol, col, lab in (("quorum", "#1f78b4", "2f + 1 policy"), ("strict", "#33a02c", "n - f policy")):
        s_ = sw[sw.policy == pol]
        ax.plot(s_["malicious_validators"], s_["poison_committed"], "o-", color=col, label=f"Poisoned, {lab}")
        ax.plot(s_["malicious_validators"], s_["honest_committed"], "s--", color=col, alpha=0.6, label=f"Honest, {lab}")
    ax.set_xlabel(f"Malicious validators k (n = {n})"); ax.set_ylabel("Signatures committed")
    ax.legend(frameon=False, fontsize=7)
    fig.savefig("figures/fig_byzantine.png"); plt.close(fig)


def overhead():
    d = pd.DataFrame(json.load(open("results/overhead.json")))
    g = d.groupby(["system", "n", "T"]).agg(["mean", "std"]).reset_index()
    cols = ["throughput_sig_per_s", "block_latency_s_mean", "block_latency_s_p95", "bytes_total", "cpu_s_total", "ledger_bytes_per_node"]
    flat = pd.DataFrame({"system": g["system"], "n": g["n"], "T": g["T"]})
    for c in cols:
        flat[c + "_mean"] = g[(c, "mean")]; flat[c + "_std"] = g[(c, "std")]
    flat.to_csv("results/tables/table_overhead.csv", index=False)
    Tmax = d["T"].max()
    fig, ax = plt.subplots(1, 3, figsize=(10.5, 3))
    for s in ("ledger", "pubsub"):
        sub = flat[(flat.system == s) & (flat["T"] == Tmax)]
        lab = "Permissioned ledger" if s == "ledger" else "Authenticated publish-subscribe"
        ax[0].errorbar(sub.n, 1000 * sub.block_latency_s_mean_mean, 1000 * sub.block_latency_s_mean_std, marker="o", color=C[s], label=lab, capsize=2)
        ax[1].errorbar(sub.n, sub.throughput_sig_per_s_mean, sub.throughput_sig_per_s_std, marker="o", color=C[s], capsize=2)
        ax[2].errorbar(sub.n, sub.bytes_total_mean / Tmax / 1024, sub.bytes_total_std / Tmax / 1024, marker="o", color=C[s], capsize=2)
    ax[0].set_ylabel("Latency per 50-signature block (ms)"); ax[1].set_ylabel("Signatures per second"); ax[2].set_ylabel("KiB sent per signature")
    for a, t in zip(ax, ["(a) Commit latency", "(b) Throughput", "(c) Communication"]):
        a.set_xlabel("Validators or subscribers (n)"); a.set_title(t)
    ax[0].legend(frameon=False)
    fig.savefig("figures/fig_overhead.png"); plt.close(fig)


if __name__ == "__main__":
    for fn in (detection, collab, overhead):
        try:
            fn(); print(fn.__name__, "done")
        except FileNotFoundError as e:
            print(fn.__name__, "skipped:", e)
