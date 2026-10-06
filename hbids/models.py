"""Phase-2 classifier ensemble: MLP, XGBoost and Random Forest with majority voting."""
from __future__ import annotations

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import QuantileTransformer
from xgboost import XGBClassifier


class Ensemble:
    def __init__(self, cfg: dict, seed: int):
        e = cfg["ensemble"]
        self.models = {
            "MLP": make_pipeline(QuantileTransformer(n_quantiles=200, output_distribution="normal", random_state=seed),
                                 MLPClassifier(**{**e["mlp"], "hidden_layer_sizes": tuple(e["mlp"]["hidden_layer_sizes"])},
                                               random_state=seed)),
            "XGBoost": XGBClassifier(**e["xgb"], random_state=seed, n_jobs=-1, eval_metric="logloss", verbosity=0),
            "RandomForest": RandomForestClassifier(**e["rf"], random_state=seed),
        }

    def fit(self, X, y):
        for m in self.models.values():
            m.fit(X, y)
        return self

    def member_proba(self, X) -> dict[str, np.ndarray]:
        return {k: m.predict_proba(X)[:, 1] for k, m in self.models.items()}

    def predict(self, X, probs: dict | None = None):
        probs = probs or self.member_proba(X)
        votes = sum((p >= 0.5).astype(int) for p in probs.values())
        return (votes >= 2).astype(np.int8)

    def score(self, X, probs: dict | None = None):
        probs = probs or self.member_proba(X)
        return np.mean(list(probs.values()), axis=0)
