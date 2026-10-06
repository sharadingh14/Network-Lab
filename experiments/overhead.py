"""Stage 4: cost of the permissioned ledger versus authenticated pub-sub.

For n validators (or subscribers) and T signature transactions submitted in blocks of
batch_size, measures: end-to-end commit latency per block (until every honest replica has
committed), throughput (signatures per second), bytes sent, CPU seconds, and ledger growth.
All processes run on one host over loopback TCP, so network propagation delay is not included.
Output: results/overhead.json"""
import json
import os
import sys
import time

import numpy as np
import yaml

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from hbids.ledger.cluster import LedgerCluster, PubSub  # noqa: E402
from hbids.signatures import BenignReference, make_signature  # noqa: E402


def synthetic_signatures(T, rng):
    # Structure identical to real signatures; contents are random keys (cost does not depend on content).
    return [make_signature(np.concatenate([[6, int(rng.integers(1, 65535))], rng.integers(0, 24, 5)]),
                           ["f1", "f2", "f3", "f4", "f5"], 50, "ids0") for _ in range(T)]


def main(cfg_path="configs/default.yaml"):
    cfg = yaml.safe_load(open(cfg_path))
    oc, bs = cfg["overhead"], cfg["ledger"]["batch_size"]
    rng = np.random.default_rng(0)
    ref = BenignReference(np.arange(50000, dtype=np.int64))
    out = []
    port = 48000
    for n in oc["validator_counts"]:
        for T in oc["tx_counts"]:
            for rep in range(oc["repetitions"]):
                sigs = synthetic_signatures(T, rng)
                port += 50
                c = LedgerCluster(n, ["ids0"], [ref], 0.0005, 20, base_port=port)
                txs = [c.make_tx("ids0", s) for s in sigs]
                t0 = time.perf_counter()
                lats, client_bytes = [], 0
                for i in range(0, T, bs):
                    r = c.submit(txs[i:i + bs])
                    lats.append(r["latency_all_s"]); client_bytes += r["client_bytes"]
                wall = time.perf_counter() - t0
                st = c.shutdown()
                out.append({"system": "ledger", "n": n, "T": T, "rep": rep, "wall_s": wall,
                            "throughput_sig_per_s": T / wall, "block_latency_s_mean": float(np.mean(lats)),
                            "block_latency_s_p95": float(np.percentile(lats, 95)),
                            "bytes_total": client_bytes + sum(s["bytes_sent"] for s in st),
                            "cpu_s_total": sum(s["cpu_s"] for s in st),
                            "ledger_bytes_per_node": float(np.mean([s["ledger_bytes"] for s in st])),
                            "rss_mb_mean": float(np.mean([s["rss_mb"] for s in st]))})
                p = PubSub(n, ["ids0"])
                txs = [p.make_tx("ids0", s) for s in sigs]
                t0 = time.perf_counter(); lats, b = [], 0
                for i in range(0, T, bs):
                    r = p.publish(txs[i:i + bs]); lats.append(r["latency_all_s"]); b += r["bytes"]
                wall = time.perf_counter() - t0
                st = p.shutdown()
                out.append({"system": "pubsub", "n": n, "T": T, "rep": rep, "wall_s": wall,
                            "throughput_sig_per_s": T / wall, "block_latency_s_mean": float(np.mean(lats)),
                            "block_latency_s_p95": float(np.percentile(lats, 95)),
                            "bytes_total": b, "cpu_s_total": sum(s["cpu_s"] for s in st),
                            "ledger_bytes_per_node": 0.0})
                print(out[-2]["n"], T, rep, round(out[-2]["throughput_sig_per_s"], 1),
                      round(out[-1]["throughput_sig_per_s"], 1), flush=True)
                json.dump(out, open("results/overhead.json", "w"), indent=1)


if __name__ == "__main__":
    main(*sys.argv[1:])
