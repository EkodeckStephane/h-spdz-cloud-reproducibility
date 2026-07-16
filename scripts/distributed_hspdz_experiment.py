"""
Local multi-process H-SPDZ-Cloud transition benchmark.

Each lower-level source party is executed in a separate Python process. The
coordinator supplies the already-authenticated lower-level share, receives
verifiable resharing openings, checks Pedersen conservation, and authenticates
the accepted upper-level sharing. Configurable link delays emulate
edge/fog/cloud communication without requiring multiple physical machines.
"""

from __future__ import annotations

import argparse
import csv
import multiprocessing as mp
import time
from pathlib import Path
from typing import Dict, List

import numpy as np

import hspdz_vss
from hspdz_cloud_implementation import HSPDZCloud, AuthenticatedShare, P, field_bytes, rand_field


FIELD_BYTES = field_bytes(P)
BLIND_BYTES = 32
COMMITMENT_BYTES = 64


def _source_party_worker(inbox: mp.Queue, outbox: mp.Queue) -> None:
    while True:
        task = inbox.get()
        if task is None:
            return

        source_id = task["source_id"]
        n_next = task["n_next"]
        share = task["share"]
        rho = task["rho"]
        corrupt = task["corrupt"]
        delay_ms = task["delay_ms"]

        if delay_ms:
            time.sleep(delay_ms / 1000.0)

        source_value = (share + 1) % P if corrupt else share
        subshares = [rand_field() for _ in range(n_next - 1)]
        subshares.append(source_value - sum(subshares))

        blinds = [hspdz_vss.random_blind() for _ in range(n_next - 1)]
        blinds.append((rho - sum(blinds)) % hspdz_vss.curve_order)
        subcommitments = [hspdz_vss.commit(subshares[j], blinds[j]) for j in range(n_next)]

        if delay_ms:
            time.sleep(delay_ms / 1000.0)

        outbox.put(
            {
                "source_id": source_id,
                "subshares": subshares,
                "blinds": blinds,
                "commitments": subcommitments,
                "bytes": n_next * (FIELD_BYTES + BLIND_BYTES + COMMITMENT_BYTES),
            }
        )


class LocalDistributedTransition:
    def __init__(self, level_sizes: List[int], link_delay_ms: float):
        self.proto = HSPDZCloud(level_sizes)
        self.link_delay_ms = link_delay_ms

    def run_once(self, secret: int, corrupt_sources: List[int] | None = None) -> Dict:
        corrupt_sources = corrupt_sources or []
        shared = self.proto.share_secret(secret, 0)
        commit_data = self.proto.commit_transition(shared, 1)
        n_curr = self.proto.level_sizes[0]
        n_next = self.proto.level_sizes[1]

        inboxes = [mp.Queue() for _ in range(n_curr)]
        outbox = mp.Queue()
        workers = [
            mp.Process(target=_source_party_worker, args=(inboxes[i], outbox))
            for i in range(n_curr)
        ]

        start = time.perf_counter()
        for worker in workers:
            worker.start()

        for i in range(n_curr):
            inboxes[i].put(
                {
                    "source_id": i,
                    "n_next": n_next,
                    "share": int(shared.shares[i]),
                    "rho": commit_data["commitment_blinds"][i],
                    "corrupt": i in corrupt_sources,
                    "delay_ms": self.link_delay_ms,
                }
            )

        responses = [outbox.get(timeout=30) for _ in range(n_curr)]
        for inbox in inboxes:
            inbox.put(None)
        for worker in workers:
            worker.join(timeout=10)

        new_shares = np.zeros(n_next, dtype=object)
        malicious = []
        bytes_sent = 0
        by_source = {r["source_id"]: r for r in responses}

        for i in range(n_curr):
            response = by_source[i]
            bytes_sent += response["bytes"]
            openings_valid = all(
                hspdz_vss.equal(
                    hspdz_vss.commit(response["subshares"][j], response["blinds"][j]),
                    response["commitments"][j],
                )
                for j in range(n_next)
            )
            conservation_valid = (
                (sum(response["subshares"]) - int(shared.shares[i])) % P == 0
                and hspdz_vss.equal(
                    hspdz_vss.combine(response["commitments"]),
                    commit_data["value_commitments"][i],
                )
            )
            if not openings_valid or not conservation_valid:
                malicious.append(i)
            for j in range(n_next):
                new_shares[j] = (new_shares[j] + response["subshares"][j]) % P

        accepted = not malicious
        mac_ok = False
        if accepted:
            transitioned = AuthenticatedShare(
                new_shares,
                self.proto._authenticate_value_shares(new_shares, 1),
                1,
            )
            accepted = self.proto.reconstruct(transitioned) == secret
            mac_ok = self.proto.verify_mac(transitioned)

        elapsed_ms = (time.perf_counter() - start) * 1000.0
        return {
            "secret": secret,
            "n_edge": n_curr,
            "n_fog": n_next,
            "delay_ms": self.link_delay_ms,
            "latency_ms": elapsed_ms,
            "bytes": bytes_sent,
            "accepted": accepted,
            "mac_ok": mac_ok,
            "malicious": ";".join(str(x) for x in malicious),
        }


def run_benchmark(output: Path, runs: int, delays: List[float]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    for delay in delays:
        runner = LocalDistributedTransition([5, 3, 2], delay)
        for idx in range(runs):
            rows.append(runner.run_once(1000 + idx))
        rows.append(runner.run_once(9999, corrupt_sources=[1]))

    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--delays", type=float, nargs="+", default=[0.2, 2.0, 10.0])
    parser.add_argument("--output", type=Path, default=Path("results/distributed_transition_results.csv"))
    args = parser.parse_args()
    run_benchmark(args.output, args.runs, args.delays)
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    mp.freeze_support()
    main()
