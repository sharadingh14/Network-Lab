"""Genetic-algorithm feature selection.

Chromosome: binary mask over the candidate features.
Fitness: macro-F1 of a Random Forest trained on the earlier 75 % and scored on the
later 25 % of every (day, label) group of the training portion (chronological order),
minus a small penalty per selected feature.
"""
from __future__ import annotations

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score


def ga_select(X: np.ndarray, y: np.ndarray, t: np.ndarray, cfg: dict, seed: int, log: list | None = None,
              groups: np.ndarray | None = None) -> np.ndarray:
    g = cfg["ga"]
    rng = np.random.default_rng(seed)
    n = X.shape[1]
    # chronological validation split inside the training data, applied within every group
    # (day, label), mirroring the main split, so that every attack type appears in both parts
    if groups is None:
        groups = np.zeros(len(t), dtype=int)
    tr_parts, va_parts = [], []
    for gval in np.unique(groups):
        idx = np.where(groups == gval)[0]
        idx = idx[np.argsort(t[idx], kind="stable")]
        cut = int(round(len(idx) * (1 - g["validation_fraction"])))
        tr_parts.append(idx[:cut]); va_parts.append(idx[cut:])
    tr_idx, va_idx = np.concatenate(tr_parts), np.concatenate(va_parts)
    if len(tr_idx) > g["fitness_subsample"]:
        tr_idx = rng.choice(tr_idx, g["fitness_subsample"], replace=False)
    if len(va_idx) > g["fitness_subsample"]:
        va_idx = rng.choice(va_idx, g["fitness_subsample"], replace=False)
    Xtr, ytr, Xva, yva = X[tr_idx], y[tr_idx], X[va_idx], y[va_idx]
    pm = g["mutation_rate"] or 1.0 / n
    cache: dict[bytes, float] = {}

    def fitness(mask: np.ndarray) -> float:
        k = mask.tobytes()
        if k in cache:
            return cache[k]
        if mask.sum() == 0:
            cache[k] = -1.0
            return -1.0
        m = RandomForestClassifier(n_estimators=g["fitness_model"]["n_estimators"],
                                   max_depth=g["fitness_model"]["max_depth"],
                                   n_jobs=-1, random_state=seed)
        m.fit(Xtr[:, mask], ytr)
        f = f1_score(yva, m.predict(Xva[:, mask]), average="macro") - g["feature_penalty"] * mask.sum()
        cache[k] = float(f)
        return cache[k]

    pop = rng.random((g["population"], n)) < 0.5
    pop[0] = True  # include the all-features individual
    for gen in range(g["generations"]):
        fit = np.array([fitness(ind) for ind in pop])
        if log is not None:
            log.append({"generation": gen, "best": float(fit.max()), "mean": float(fit.mean()),
                        "n_features_best": int(pop[fit.argmax()].sum())})
        elite = pop[np.argsort(fit)[::-1][: g["elitism"]]]
        children = [e.copy() for e in elite]
        while len(children) < g["population"]:
            def tourney():
                c = rng.choice(len(pop), g["tournament_size"], replace=False)
                return pop[c[np.argmax(fit[c])]]
            p1, p2 = tourney(), tourney()
            if rng.random() < g["crossover_rate"]:
                m = rng.random(n) < 0.5
                child = np.where(m, p1, p2)
            else:
                child = p1.copy()
            flip = rng.random(n) < pm
            child = np.logical_xor(child, flip)
            children.append(child)
        pop = np.array(children)
    fit = np.array([fitness(ind) for ind in pop])
    return pop[fit.argmax()]
