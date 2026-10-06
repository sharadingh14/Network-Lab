"""Launches validator processes and acts as the IDS initiator client.

Also contains the non-blockchain baseline: authenticated publish-subscribe, in which an
initiator signs each signature and pushes it directly to every peer; peers check only the
initiator's ECDSA signature and membership (no quorum, no benign-traffic validation, no ledger).
"""
from __future__ import annotations

import asyncio
import multiprocessing as mp
import os
import socket
import tempfile
import time

from .crypto import Identity, Registry, canonical
from .node import recv_msg, run_validator, send_msg


def free_port_block(n: int, start: int) -> int:
    base = start
    while True:
        ok = True
        for j in range(n + 1):
            with socket.socket() as s:
                try:
                    s.bind(("127.0.0.1", base + j))
                except OSError:
                    ok = False
                    break
        if ok:
            return base
        base += n + 7


class LedgerCluster:
    def __init__(self, n: int, initiators: list[str], benign_refs: list, tolerance: float, min_support: int,
                 behaviours: list[str] | None = None, base_port: int = 47000, policy: str = "quorum"):
        self.n = n
        self.f = (n - 1) // 3
        self.vids = [Identity(f"v{i}") for i in range(n)]
        self.iids = {name: Identity(name) for name in initiators}
        pems = {i.name: i.public_pem() for i in self.vids}
        pems.update({k: v.public_pem() for k, v in self.iids.items()})
        self.registry = Registry(pems)
        self.base = free_port_block(n, base_port)
        self.ledger_dir = tempfile.mkdtemp(prefix="hbids_ledger_")
        behaviours = behaviours or ["honest"] * n
        ctx = mp.get_context("spawn")
        self.procs = []
        readies = []
        for i in range(n):
            ref = benign_refs[i % len(benign_refs)]
            ev = ctx.Event()
            kw = dict(idx=i, n=n, base_port=self.base, priv_pem=self.vids[i].private_pem(), registry_pems=pems,
                      benign_counts=ref.counts, benign_total=ref.total, tolerance=tolerance,
                      min_support=min_support, behaviour=behaviours[i], ledger_dir=self.ledger_dir,
                      policy=policy)
            p = ctx.Process(target=run_validator, args=(kw, ev), daemon=True)
            p.start()
            self.procs.append(p)
            readies.append(ev)
        for ev in readies:
            ev.wait(30)
        self.behaviours = behaviours

    def make_tx(self, origin: str, payload: dict) -> dict:
        return {"origin": origin, "payload": payload, "sig": self.iids[origin].sign(payload)}

    async def _submit(self, txs: list[dict], endorse_timeout: float):
        n_honest = sum(b != "crash" for b in self.behaviours)
        replies, first = [], asyncio.get_event_loop().create_future()
        done_all = asyncio.get_event_loop().create_future()

        async def on_reply(r, w):
            m = await recv_msg(r)
            replies.append((time.perf_counter(), m))
            if len(replies) == self.f + 1 and not first.done():
                first.set_result(True)
            if len(replies) == n_honest and not done_all.done():
                done_all.set_result(True)
            w.close()

        srv = await asyncio.start_server(on_reply, "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        r, w = await asyncio.open_connection("127.0.0.1", self.base)
        t0 = time.perf_counter()
        sent = await send_msg(w, {"type": "SUBMIT", "client": "c", "client_port": port, "txs": txs,
                                  "endorse_timeout": endorse_timeout})
        try:
            await asyncio.wait_for(first, 20)
            t1 = time.perf_counter()
            await asyncio.wait_for(done_all, 20)
            t2 = time.perf_counter()
        except asyncio.TimeoutError:
            t1 = t2 = float("nan")
        w.close()
        srv.close()
        committed = set(replies[0][1]["committed"]) if replies else set()
        return {"latency_f1_s": t1 - t0, "latency_all_s": t2 - t0, "committed": committed, "client_bytes": sent}

    def submit(self, txs: list[dict], endorse_timeout: float = 1.0) -> dict:
        return asyncio.run(self._submit(txs, endorse_timeout))

    def shutdown(self) -> list[dict]:
        async def go():
            out = []
            for i in range(self.n):
                if self.behaviours[i] == "crash":
                    # crashed validators still need to exit cleanly
                    pass
                try:
                    r, w = await asyncio.open_connection("127.0.0.1", self.base + i)
                    await send_msg(w, {"type": "SHUTDOWN"})
                    out.append(await asyncio.wait_for(recv_msg(r), 5))
                    w.close()
                except Exception:
                    pass
            return out
        stats = asyncio.run(go())
        for p in self.procs:
            p.join(5)
            if p.is_alive():
                p.terminate()
        return stats


# ---------------------------------------------------------------------------------------------
# Non-blockchain baseline: authenticated publish-subscribe
# ---------------------------------------------------------------------------------------------
async def _subscriber(port_holder, ready, registry_pems, stop_after, result_q):
    reg = Registry(registry_pems)
    accepted = []
    stop = asyncio.Event()

    async def serve(r, w):
        try:
            while True:
                m = await recv_msg(r)
                if m["type"] == "STOP":
                    import psutil
                    ct = psutil.Process().cpu_times()
                    await send_msg(w, {"accepted": len(accepted), "cpu_s": ct.user + ct.system - cpu0})
                    stop.set()
                    return
                ok = [reg.verify(tx["origin"], tx["payload"], tx["sig"]) for tx in m["txs"]]
                accepted.extend(tx["payload"]["sig_id"] for tx, o in zip(m["txs"], ok) if o)
                await send_msg(w, {"ack": [tx["payload"]["sig_id"] for tx, o in zip(m["txs"], ok) if o]})
        except asyncio.IncompleteReadError:
            return

    srv = await asyncio.start_server(serve, "127.0.0.1", 0)
    import psutil
    ct0 = psutil.Process().cpu_times()
    cpu0 = ct0.user + ct0.system
    port_holder.value = srv.sockets[0].getsockname()[1]
    ready.set()
    async with srv:
        await stop.wait()


def run_subscriber(port_holder, ready, registry_pems):
    asyncio.run(_subscriber(port_holder, ready, registry_pems, None, None))


class PubSub:
    def __init__(self, n: int, initiators: list[str]):
        self.n = n
        self.iids = {name: Identity(name) for name in initiators}
        pems = {k: v.public_pem() for k, v in self.iids.items()}
        ctx = mp.get_context("spawn")
        self.procs, self.ports = [], []
        for _ in range(n):
            ph, ev = ctx.Value("i", 0), ctx.Event()
            p = ctx.Process(target=run_subscriber, args=(ph, ev, pems), daemon=True)
            p.start()
            ev.wait(30)
            self.procs.append(p)
            self.ports.append(ph.value)
        self.conns = None

    def make_tx(self, origin: str, payload: dict) -> dict:
        return {"origin": origin, "payload": payload, "sig": self.iids[origin].sign(payload)}

    async def _publish(self, txs):
        if self.conns is None:
            self.conns = [await asyncio.open_connection("127.0.0.1", p) for p in self.ports]
        t0 = time.perf_counter()
        sent = 0
        for _, w in self.conns:
            sent += await send_msg(w, {"type": "PUB", "txs": txs})
        acks = await asyncio.gather(*(recv_msg(r) for r, _ in self.conns))
        t = time.perf_counter() - t0
        return {"latency_all_s": t, "bytes": sent, "accepted": set(acks[0]["ack"])}

    def publish(self, txs):
        loop = getattr(self, "_loop", None) or asyncio.new_event_loop()
        self._loop = loop
        return loop.run_until_complete(self._publish(txs))

    def shutdown(self):
        async def go():
            out = []
            for r, w in self.conns or []:
                await send_msg(w, {"type": "STOP"})
                out.append(await recv_msg(r))
            return out
        stats = self._loop.run_until_complete(go()) if self.conns else []
        for p in self.procs:
            p.join(5)
            if p.is_alive():
                p.terminate()
        return stats
