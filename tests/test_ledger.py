"""Functional test of the ledger: honest signatures commit, poisoned ones are rejected,
and a minority of malicious validators cannot force a poisoned signature in."""
import numpy as np
from hbids.signatures import BenignReference, make_signature, key_hash
from hbids.ledger.cluster import LedgerCluster, PubSub


def refs():
    benign_keys = np.array([[6, 443, 1, 1, 1, 1], [17, 53, 0, 0, 0, 0]] * 500)
    return [BenignReference(key_hash(benign_keys))]


def sigs():
    good = make_signature(np.array([6, 21, 3, 3, 2, 1]), ["a", "b", "c", "d"], 50, "ids0")
    poison = make_signature(np.array([6, 443, 1, 1, 1, 1]), ["a", "b", "c", "d"], 50, "ids1")
    return good, poison


def run(behaviours, policy="quorum"):
    c = LedgerCluster(4, ["ids0", "ids1"], refs(), 0.0005, 20, behaviours=behaviours, base_port=47100, policy=policy)
    good, poison = sigs()
    r = c.submit([c.make_tx("ids0", good), c.make_tx("ids1", poison)], endorse_timeout=0.5)
    st = c.shutdown()
    return r, st, good, poison


def test_honest():
    r, st, good, poison = run(["honest"] * 4)
    assert good["sig_id"] in r["committed"] and poison["sig_id"] not in r["committed"]
    assert all(s["height"] == 1 for s in st)


def test_one_malicious_one_crash():
    r, st, good, poison = run(["honest", "malicious", "honest", "honest"])
    assert good["sig_id"] in r["committed"] and poison["sig_id"] not in r["committed"]
    r, st, good, poison = run(["honest", "honest", "crash", "honest"])
    assert good["sig_id"] in r["committed"]


def test_strict_policy():
    # n = 4, f = 1: strict policy needs n - f = 3 endorsements; one crash still allows commits
    r, st, good, poison = run(["honest"] * 4, "strict")
    assert good["sig_id"] in r["committed"] and poison["sig_id"] not in r["committed"]
    r, st, good, poison = run(["honest", "malicious", "honest", "honest"], "strict")
    assert poison["sig_id"] not in r["committed"]


def test_pubsub_accepts_poison():
    p = PubSub(3, ["ids0", "ids1"])
    good, poison = sigs()
    r = p.publish([p.make_tx("ids0", good), p.make_tx("ids1", poison)])
    p.shutdown()
    assert poison["sig_id"] in r["accepted"]


if __name__ == "__main__":
    test_honest(); test_one_malicious_one_crash(); test_strict_policy(); test_pubsub_accepts_poison(); print("ledger tests passed")
