"""Evaluation metrics. False alarm rate is defined as the false-positive rate:
FAR = FP / (FP + TN), i.e. the fraction of benign flows raised as alerts."""
from __future__ import annotations

import numpy as np
from sklearn.metrics import average_precision_score, confusion_matrix, roc_auc_score


def binary_metrics(y: np.ndarray, pred: np.ndarray, score: np.ndarray | None = None) -> dict:
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    spec = tn / (tn + fp) if tn + fp else 0.0
    f1_neg = 2 * tn / (2 * tn + fn + fp) if tn else 0.0
    out = {
        "TP": int(tp), "FP": int(fp), "TN": int(tn), "FN": int(fn),
        "accuracy": (tp + tn) / (tp + tn + fp + fn),
        "precision": prec, "recall": rec, "f1": f1,
        "macro_f1": (f1 + f1_neg) / 2,
        "FAR": fp / (fp + tn) if fp + tn else 0.0,
        "FNR": fn / (fn + tp) if fn + tp else 0.0,
        "balanced_accuracy": (rec + spec) / 2,
    }
    if score is not None and len(np.unique(y)) == 2:
        out["roc_auc"] = float(roc_auc_score(y, score))
        out["pr_auc"] = float(average_precision_score(y, score))
    return {k: (float(v) if isinstance(v, (np.floating, float)) else v) for k, v in out.items()}


def per_family_recall(families: np.ndarray, y: np.ndarray, pred: np.ndarray) -> dict:
    out = {}
    for f in np.unique(families):
        m = families == f
        if f == "Benign":
            out[f] = {"n": int(m.sum()), "specificity": float((pred[m] == 0).mean())}
        else:
            out[f] = {"n": int(m.sum()), "recall": float((pred[m] == 1).mean())}
    return out
