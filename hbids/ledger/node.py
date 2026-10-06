"""Permissioned signature ledger: validator process.

Protocol (endorse -> order -> commit), all messages ECDSA-signed and sent over TCP:

1. SUBMIT      initiator -> primary         batch of signed signature transactions
2. ENDORSE_REQ primary   -> all validators  candidate transactions
3. ENDORSE     validator -> primary         signed bitmap: which transactions pass this validator's checks
                                            (initiator signature and membership, minimum support, and
                                            benign-match fraction on the validator's own benign traffic)
4. PRE_PREPARE primary   -> all             block = transactions with >= 2f+1 endorsements, plus the
                                            endorsement certificates
5. PREPARE / COMMIT  all -> all             PBFT three-phase agreement on the block digest; every replica
                                            re-checks the certificates before PREPARE, so a faulty primary
                                            cannot insert an under-endorsed transaction
6. REPLY       validator -> initiator       after 2f+1 COMMITs the block is appended to the local ledger file

Simplification (stated in the paper): the primary is fixed; view change is not implemented.
Behaviours: "honest", "malicious" (endorses every transaction), "crash" (never answers).
"""
from __future__ import annotations

import asyncio
import json
import os
import struct
import time

from .crypto import Identity, Registry, canonical, merkle_root, sha256


async def send_msg(writer: asyncio.StreamWriter, obj: dict) -> int:
    b = canonical(obj)
    writer.write(struct.pack(">I", len(b)) + b)
    await writer.drain()
    return len(b) + 4


async def recv_msg(reader: asyncio.StreamReader) -> dict:
    n = struct.unpack(">I", await reader.readexactly(4))[0]
    return json.loads(await reader.readexactly(n))


class Validator:
    def __init__(self, idx: int, n: int, base_port: int, priv_pem: str, registry_pems: dict,
                 benign_counts: dict, benign_total: int, tolerance: float, min_support: int,
                 behaviour: str, ledger_dir: str, policy: str = "quorum"):
        self.idx, self.n, self.base = idx, n, base_port
        self.f = (n - 1) // 3
        self.q = 2 * self.f + 1
        # Endorsements required to admit a transaction:
        #   "quorum": 2f + 1 (a signature needs a Byzantine quorum of approvals)
        #   "strict": n - f  (a signature is rejected if more than f validators object)
        self.need = self.q if policy == "quorum" else self.n - self.f
        self.me = Identity.from_private_pem(f"v{idx}", priv_pem)
        self.reg = Registry(registry_pems)
        self.benign = benign_counts
        self.benign_total = max(benign_total, 1)
        self.tol, self.min_support = tolerance, min_support
        self.behaviour = behaviour
        self.ledger_path = os.path.join(ledger_dir, f"ledger_v{idx}.jsonl")
        self.height, self.prev = 0, sha256(b"genesis")
        self.peers: dict[int, tuple] = {}
        self.prepares: dict[str, dict] = {}
        self.commits: dict[str, dict] = {}
        self.blocks: dict[str, dict] = {}
        self.done: set[str] = set()
        self.sent_commit: set[str] = set()
        self.endorse_wait: dict[int, asyncio.Future] = {}
        self.endorsements: dict[int, dict] = {}
        self.clients: dict[str, asyncio.StreamWriter] = {}
        self.bytes_sent = 0
        self.seq = 0
        open(self.ledger_path, "w").close()

    # ---------- networking ----------
    async def peer(self, j: int):
        if j not in self.peers:
            r, w = await asyncio.open_connection("127.0.0.1", self.base + j)
            await send_msg(w, {"type": "HELLO", "from": self.idx})
            self.peers[j] = (r, w)
        return self.peers[j][1]

    async def to(self, j: int, msg: dict):
        if j == self.idx:
            await self.handle(msg, None)
            return
        w = await self.peer(j)
        self.bytes_sent += await send_msg(w, msg)

    async def broadcast(self, msg: dict):
        await asyncio.gather(*(self.to(j, msg) for j in range(self.n)))

    def signed(self, body: dict) -> dict:
        return {**body, "from": self.idx, "sig": self.me.sign(body)}

    def check(self, msg: dict) -> bool:
        body = {k: v for k, v in msg.items() if k not in ("from", "sig")}
        return self.reg.verify(f"v{msg['from']}", body, msg["sig"])

    # ---------- validation of a signature transaction ----------
    def tx_ok(self, tx: dict) -> bool:
        if self.behaviour == "malicious":
            return True
        if not self.reg.verify(tx["origin"], tx["payload"], tx["sig"]):
            return False
        p = tx["payload"]
        if p.get("support", 0) < self.min_support:
            return False
        from ..signatures import sig_hash
        frac = self.benign.get(sig_hash(p), 0) / self.benign_total
        return frac <= self.tol

    # ---------- message handling ----------
    async def handle(self, m: dict, writer):
        t = m["type"]
        if self.behaviour == "crash" and t != "SHUTDOWN":
            return
        if t == "SUBMIT":                                    # primary only
            self.clients[m["client"]] = writer
            asyncio.ensure_future(self.order(m))
        elif t == "ENDORSE_REQ":
            if not self.check(m):
                return
            bitmap = [self.tx_ok(tx) for tx in m["txs"]]
            await self.to(0, self.signed({"type": "ENDORSE", "seq": m["seq"], "digest": m["digest"], "bitmap": bitmap}))
        elif t == "ENDORSE" and self.idx == 0:
            if self.check(m) and m["seq"] in self.endorsements:
                self.endorsements[m["seq"]][m["from"]] = m
                fut = self.endorse_wait.get(m["seq"])
                if fut and not fut.done() and len(self.endorsements[m["seq"]]) >= self.n_alive_expected:
                    fut.set_result(True)
        elif t == "PRE_PREPARE":
            if not self.check(m) or m["from"] != 0:
                return
            blk = m["block"]
            if not self.block_ok(blk):
                return
            d = blk["header"]["digest"]
            self.blocks[d] = blk
            await self.broadcast(self.signed({"type": "PREPARE", "digest": d}))
            await self.progress(d)
        elif t in ("PREPARE", "COMMIT"):
            if not self.check(m):
                return
            store = self.prepares if t == "PREPARE" else self.commits
            store.setdefault(m["digest"], {})[m["from"]] = True
            await self.progress(m["digest"])

    async def progress(self, d: str):
        """Advance PBFT state for block digest d regardless of message arrival order."""
        if d not in self.blocks:
            return
        if len(self.prepares.get(d, {})) >= self.q and d not in self.sent_commit:
            self.sent_commit.add(d)
            await self.broadcast(self.signed({"type": "COMMIT", "digest": d}))
        if len(self.commits.get(d, {})) >= self.q and d not in self.done:
            self.done.add(d)
            self.append(self.blocks[d])
            await self.reply(self.blocks[d])

    def block_ok(self, blk: dict) -> bool:
        h = blk["header"]
        if merkle_root([sha256(canonical(tx)) for tx in blk["txs"]]) != h["merkle_root"]:
            return False
        for tx, cert in zip(blk["txs"], blk["certs"]):
            ok = 0
            for e in cert:
                body = {k: v for k, v in e["endorsement"].items() if k not in ("from", "sig")}
                if self.reg.verify(f"v{e['endorsement']['from']}", body, e["endorsement"]["sig"]) and \
                        e["endorsement"]["bitmap"][e["pos"]]:
                    ok += 1
            if ok < self.need:
                return False
        return True

    def append(self, blk: dict):
        with open(self.ledger_path, "a") as f:
            f.write(json.dumps(blk) + "\n")
        self.height += 1
        self.prev = blk["header"]["digest"]

    async def reply(self, blk: dict):
        r, w = await asyncio.open_connection("127.0.0.1", blk["header"]["client_port"])
        self.bytes_sent += await send_msg(w, {"type": "REPLY", "from": self.idx, "digest": blk["header"]["digest"],
                                              "committed": [tx["payload"]["sig_id"] for tx in blk["txs"]],
                                              "t": time.time()})
        w.close()

    async def order(self, sub: dict):
        txs = sub["txs"]
        self.seq += 1
        seq = self.seq
        digest = sha256(canonical(txs))
        self.endorsements[seq] = {}
        self.n_alive_expected = self.n
        fut = asyncio.get_event_loop().create_future()
        self.endorse_wait[seq] = fut
        await self.broadcast(self.signed({"type": "ENDORSE_REQ", "seq": seq, "digest": digest, "txs": txs}))
        try:
            await asyncio.wait_for(fut, timeout=sub.get("endorse_timeout", 1.0))
        except asyncio.TimeoutError:
            pass
        ends = self.endorsements[seq]
        keep, certs = [], []
        for i, tx in enumerate(txs):
            c = [{"endorsement": e, "pos": i} for e in ends.values() if e["bitmap"][i]]
            if len(c) >= self.need:
                keep.append(tx)
                certs.append(c[: self.need])
        header = {"height": self.height + 1, "prev_hash": self.prev, "timestamp": time.time(),
                  "merkle_root": merkle_root([sha256(canonical(tx)) for tx in keep]),
                  "n_tx": len(keep), "client_port": sub["client_port"], "seq": seq}
        header["digest"] = sha256(canonical(header))
        blk = {"header": header, "txs": keep, "certs": certs,
               "rejected": [tx["payload"]["sig_id"] for tx in txs if tx not in keep]}
        await self.broadcast(self.signed({"type": "PRE_PREPARE", "block": blk}))

    # ---------- server ----------
    async def serve(self, conn_reader, conn_writer):
        try:
            while True:
                m = await recv_msg(conn_reader)
                if m["type"] == "HELLO":
                    continue
                if m["type"] == "SHUTDOWN":
                    import psutil
                    p = psutil.Process()
                    ct = p.cpu_times()
                    await send_msg(conn_writer, {"type": "STATS", "idx": self.idx, "bytes_sent": self.bytes_sent,
                                                 "cpu_s": ct.user + ct.system - self.cpu0,
                                                 "rss_mb": p.memory_info().rss / 2**20,
                                                 "ledger_bytes": os.path.getsize(self.ledger_path),
                                                 "height": self.height})
                    asyncio.get_event_loop().call_later(0.05, self.stop.set)
                    continue
                await self.handle(m, conn_writer)
        except (asyncio.IncompleteReadError, ConnectionResetError):
            return

    async def main(self, ready):
        self.stop = asyncio.Event()
        srv = await asyncio.start_server(self.serve, "127.0.0.1", self.base + self.idx)
        import psutil
        ct = psutil.Process().cpu_times()
        self.cpu0 = ct.user + ct.system          # exclude interpreter start-up from CPU accounting
        ready.set()
        async with srv:
            await self.stop.wait()


def run_validator(kwargs: dict, ready):
    v = Validator(**kwargs)
    asyncio.run(v.main(ready))
