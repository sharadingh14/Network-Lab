# HBIDS: hybrid intrusion detection with poisoning-resistant signature sharing on a permissioned ledger

Code and configuration for the revised manuscript *"Poisoning-Resistant Signature Sharing for Hybrid
Intrusion Detection Using a Permissioned Ledger"* (Singh and Sastry). Every number, table and figure in
the paper is produced by `run_all.sh`; no value is entered by hand.

## What the system does

| Phase | Component | File |
|---|---|---|
| 1 | Signature matching on discretised flow keys (Protocol, Dst Port, log2 bins of five flow counters) | `hbids/signatures.py` |
| 2 | Genetic-algorithm feature selection; ensemble of MLP, XGBoost and Random Forest with majority voting | `hbids/ga.py`, `hbids/models.py` |
| 3 | New signatures from flows flagged in Phase 2; shared through a permissioned ledger | `hbids/ledger/` |

The ledger uses an **endorse, order, commit** protocol (ECDSA P-256 signatures, SHA-256 Merkle roots,
PBFT three-phase agreement among `n` validator processes over TCP). An honest validator endorses only
signatures that match no more than 0.05 % of its own benign traffic. Two admission policies are implemented
(`policy=` in `LedgerCluster`): `quorum` commits a signature with at least `2f + 1` endorsements; `strict`
commits it only with at least `n - f` endorsements, so it is rejected when more than `f` validators object.
The non-blockchain baseline is an authenticated publish-subscribe channel (ECDSA-signed, no quorum, no ledger).

Stated simplifications: fixed primary (no view change); all processes run on one host over loopback TCP,
so wide-area propagation delay is not included in the latency figures.

## Data

CSE-CIC-IDS2018 (Sharafaldin et al., ICISSP 2018), Kaggle CSV mirror `solarmainframe/ids-intrusion-csv`.
Place these files in `data/raw/`:

```
02-14-2018.csv  02-15-2018.csv  02-16-2018.csv  02-21-2018.csv  02-22-2018.csv  03-02-2018.csv
```

Preprocessing (`hbids/data.py`, `experiments/prepare.py`):
1. remove repeated header rows, rows with missing or infinite values, and exact duplicate flows;
2. remove feature vectors that occur with more than one label;
3. sample at most 60 000 benign flows per day and 20 000 flows per attack label (uniformly, time order kept);
4. split every (day, label) group **chronologically**: oldest 60 % training, next 20 % signature window, newest 20 % evaluation;
5. remove signature-window and evaluation flows whose feature vector also occurs in training;
6. remove identifier columns (Flow ID, IP addresses, source port, timestamp). Destination port is used only by the signature module.

All counts are written to `results/data_summary.json`.

## Reproduce

```bash
pip install -r requirements.txt
./run_all.sh                    # full experiments (about 2.5 h on 2 CPU cores, 7 GB RAM)
./run_all.sh configs/smoke.yaml # 5-minute end-to-end check on synthetic fixture data (python tests/make_fixture.py first)
PYTHONPATH=. python tests/test_ledger.py
```

| Script | Output |
|---|---|
| `experiments/prepare.py` | `data/processed/split.pkl`, `results/data_summary.json` |
| `experiments/detection.py` | `results/detection.json`: component ablation, three seeds |
| `experiments/collab.py` | `results/collab.json`: per-site sharing, poisoning, Byzantine and crash sweeps |
| `experiments/overhead.py` | `results/overhead.json`: ledger versus pub-sub cost |
| `experiments/make_figures.py` | `figures/*.png`, `results/tables/*.csv` |

## Main results (from `results/`, mean of three seeds)

| Quantity | Value |
|---|---|
| Exact duplicate records removed | 1 847 084 of 6 291 449 (29.4 %) |
| HBIDS hybrid (all features): F1, false-positive rate | 99.43 %, 0.093 % |
| Recall on attack families unseen at a site: no sharing, publish-subscribe, ledger (n - f) | 27.00 %, 98.55 %, 93.07 % |
| Poisoned signatures accepted (of 50): publish-subscribe, ledger 2f + 1, ledger n - f | 50, 3, 0 |
| False-positive rate of honest sites under poisoning: publish-subscribe, ledger n - f | 43.65 %, 0.504 % |
| Commit latency per 50-signature block, 4 to 13 validators: ledger, publish-subscribe | 75 to 435 ms, 12 to 36 ms |

## Metrics

False alarm rate is the false-positive rate, `FAR = FP / (FP + TN)`. Also reported: accuracy, precision,
recall, F1, macro-F1, ROC-AUC, PR-AUC, confusion counts and per-family recall, as mean ± standard deviation over three seeds.

## Optional Hyperledger Fabric port

`fabric_chaincode/signature_cc.go` maps the same transaction and endorsement rule onto Fabric v2.5
(endorsement policy `MAJORITY Endorsement`, benign reference held in each organisation's implicit private
data collection). It was **not executed** for the paper.

## Licence

MIT.
