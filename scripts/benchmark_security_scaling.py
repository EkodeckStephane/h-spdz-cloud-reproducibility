"""61-bit versus 127-bit-prime-field primitive scaling for H-SPDZ-Cloud.

This script isolates the core arithmetic and transition primitives and measures
the same operations over a small 61-bit Mersenne field and the prototype field
p = 2^127 - 1. The latter has 127-bit binary length and is represented with
16-byte field-element encodings in the main prototype; this micro-benchmark keeps
the primitive-level comparison reproducible without treating field size as a
homogeneous security claim.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import secrets
import statistics
import sys
import time
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import hspdz_vss


FIELDS = {
    "64": 2**61 - 1,
    "128": 2**127 - 1,
}


def rand_field(p: int) -> int:
    return secrets.randbelow(p)


def share_plain(secret: int, n: int, p: int) -> list[int]:
    shares = [rand_field(p) for _ in range(n - 1)]
    shares.append((secret - sum(shares)) % p)
    return shares


def authenticate_value_shares(shares: list[int], alpha_shares: list[int], p: int) -> list[int]:
    n = len(shares)
    r = rand_field(p)
    s = rand_field(p)
    rs = (r * s) % p
    r_shares = share_plain(r, n, p)
    s_shares = share_plain(s, n, p)
    rs_shares = share_plain(rs, n, p)

    epsilon = sum((shares[i] - r_shares[i]) % p for i in range(n)) % p
    delta = sum((alpha_shares[i] - s_shares[i]) % p for i in range(n)) % p

    mac_shares = []
    for i in range(n):
        correction = epsilon * delta if i == 0 else 0
        mac_shares.append(
            (rs_shares[i] + epsilon * s_shares[i] + delta * r_shares[i] + correction) % p
        )
    return mac_shares


def make_authenticated(secret: int, n: int, p: int) -> tuple[list[int], list[int], list[int]]:
    shares = share_plain(secret, n, p)
    alpha_shares = share_plain(rand_field(p), n, p)
    mac_shares = authenticate_value_shares(shares, alpha_shares, p)
    return shares, mac_shares, alpha_shares


def op_mac_check(p: int, n_edge: int, n_fog: int, batch_size: int) -> None:
    shares, mac_shares, alpha_shares = make_authenticated(rand_field(p), n_edge, p)
    x = sum(shares) % p
    tag = sum(mac_shares) % p
    alpha = sum(alpha_shares) % p
    if tag != (alpha * x) % p:
        raise AssertionError("MAC check failed")


def op_batch_mac_check(p: int, n_edge: int, n_fog: int, batch_size: int) -> None:
    alpha_shares = share_plain(rand_field(p), n_edge, p)
    values = []
    for _ in range(batch_size):
        shares = share_plain(rand_field(p), n_edge, p)
        mac_shares = authenticate_value_shares(shares, alpha_shares, p)
        values.append((shares, mac_shares))

    transcript = hashlib.sha256()
    transcript.update(b"hspdz-batch-state-v1")
    transcript.update(str(p).encode())
    transcript.update(str(n_edge).encode())
    transcript.update(str(batch_size).encode())
    for shares, mac_shares in values:
        for share, mac_share in zip(shares, mac_shares):
            transcript.update(str(share).encode())
            transcript.update(str(mac_share).encode())
    state_digest = transcript.hexdigest()

    coefficients = []
    for j in range(batch_size):
        h = hashlib.sha256()
        h.update(b"hspdz-batch-rho-v1")
        h.update(state_digest.encode())
        h.update(str(j).encode())
        coefficients.append(int.from_bytes(h.digest(), "big") % p)

    w_shares = [0] * n_edge
    gamma_w_shares = [0] * n_edge
    for j, (shares, mac_shares) in enumerate(values):
        coeff = coefficients[j]
        for i in range(n_edge):
            w_shares[i] = (w_shares[i] + shares[i] * coeff) % p
            gamma_w_shares[i] = (gamma_w_shares[i] + mac_shares[i] * coeff) % p

    mask = rand_field(p)
    mask_shares = share_plain(mask, n_edge, p)
    mask_mac_shares = authenticate_value_shares(mask_shares, alpha_shares, p)
    u = sum((w_shares[i] - mask_shares[i]) % p for i in range(n_edge)) % p
    e_shares = [
        (gamma_w_shares[i] - mask_mac_shares[i] - u * alpha_shares[i]) % p
        for i in range(n_edge)
    ]
    if sum(e_shares) % p != 0:
        raise AssertionError("batch MAC check failed")


def op_triple_generation_proxy(p: int, n_edge: int, n_fog: int, batch_size: int) -> None:
    alpha_shares = share_plain(rand_field(p), n_edge, p)
    a = rand_field(p)
    b = rand_field(p)
    c = (a * b) % p
    for value in (a, b, c):
        shares = share_plain(value, n_edge, p)
        authenticate_value_shares(shares, alpha_shares, p)


def op_commitment_verification(p: int, n_edge: int, n_fog: int, batch_size: int) -> None:
    value = rand_field(p)
    blind = hspdz_vss.random_blind()
    commitment = hspdz_vss.commit(value, blind)
    reopened = hspdz_vss.commit(value, blind)
    if not hspdz_vss.equal(commitment, reopened):
        raise AssertionError("commitment opening failed")


def op_inter_level_resharing(p: int, n_edge: int, n_fog: int, batch_size: int) -> None:
    shares, _, _ = make_authenticated(rand_field(p), n_edge, p)
    source_commitments = []
    source_blinds = []
    subshares_by_source = []
    subblinds_by_source = []
    subcommitments_by_source = []
    new_shares = [0] * n_fog

    for share in shares:
        rho = hspdz_vss.random_blind()
        source_blinds.append(rho)
        source_commitments.append(hspdz_vss.commit(share, rho))

        subshares = [rand_field(p) for _ in range(n_fog - 1)]
        subshares.append(share - sum(subshares))
        subblinds = [hspdz_vss.random_blind() for _ in range(n_fog - 1)]
        subblinds.append((rho - sum(subblinds)) % hspdz_vss.curve_order)
        subcommitments = [
            hspdz_vss.commit(subshares[j], subblinds[j]) for j in range(n_fog)
        ]

        for j in range(n_fog):
            new_shares[j] = (new_shares[j] + subshares[j]) % p

        subshares_by_source.append(subshares)
        subblinds_by_source.append(subblinds)
        subcommitments_by_source.append(subcommitments)

    for i in range(n_edge):
        for j in range(n_fog):
            if not hspdz_vss.equal(
                hspdz_vss.commit(subshares_by_source[i][j], subblinds_by_source[i][j]),
                subcommitments_by_source[i][j],
            ):
                raise AssertionError("receiver opening failed")
        if (sum(subshares_by_source[i]) - shares[i]) % p != 0:
            raise AssertionError("subshare conservation failed")
        if not hspdz_vss.equal(
            hspdz_vss.combine(subcommitments_by_source[i]),
            source_commitments[i],
        ):
            raise AssertionError("aggregate commitment failed")

    authenticate_value_shares(new_shares, share_plain(rand_field(p), n_fog, p), p)


OPERATIONS: dict[str, Callable[[int, int, int, int], None]] = {
    "mac_check": op_mac_check,
    "batch_mac_check_8": op_batch_mac_check,
    "triple_generation_proxy": op_triple_generation_proxy,
    "commitment_verification": op_commitment_verification,
    "inter_level_resharing": op_inter_level_resharing,
}


def measure(operation: Callable[[int, int, int, int], None], p: int, args: argparse.Namespace) -> dict:
    samples = []
    for _ in range(args.warmups):
        operation(p, args.n_edge, args.n_fog, args.batch_size)
    for _ in range(args.runs):
        start = time.perf_counter_ns()
        operation(p, args.n_edge, args.n_fog, args.batch_size)
        samples.append((time.perf_counter_ns() - start) / 1_000_000)

    return {
        "mean_ms": statistics.fmean(samples),
        "stdev_ms": statistics.stdev(samples) if len(samples) > 1 else 0.0,
        "min_ms": min(samples),
        "max_ms": max(samples),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=30)
    parser.add_argument("--warmups", type=int, default=5)
    parser.add_argument("--n-edge", type=int, default=5)
    parser.add_argument("--n-fog", type=int, default=3)
    parser.add_argument("--batch-size", type=int, default=8)
    parser.add_argument("--output", type=Path, default=Path("results/security_scaling/security_scaling_results.csv"))
    parser.add_argument("--summary", type=Path, default=Path("results/security_scaling/security_scaling_summary.md"))
    args = parser.parse_args()

    rows = []
    raw = {}
    for op_name, operation in OPERATIONS.items():
        raw[op_name] = {}
        for field_name, p in FIELDS.items():
            result = measure(operation, p, args)
            raw[op_name][field_name] = result
            rows.append(
                {
                    "operation": op_name,
                    "field_bits": field_name,
                    "prime": p,
                    "n_edge": args.n_edge,
                    "n_fog": args.n_fog,
                    "batch_size": args.batch_size if "batch" in op_name else "",
                    **result,
                }
            )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    lines = [
        "# 61-bit versus 127-bit-prime-field Scaling Micro-benchmark",
        "",
        "Configuration:",
        "",
        f"- runs per operation/field: `{args.runs}` after `{args.warmups}` warmups",
        f"- lower-level parties: `{args.n_edge}`",
        f"- upper-level parties: `{args.n_fog}`",
        f"- batch size for batch MAC check: `{args.batch_size}`",
        "- small comparison field: `2^61 - 1`",
        "- prototype field: `2^127 - 1` (127-bit binary length, 16-byte encodings)",
        "- commitment backend: BN254 G1 Pedersen helper used by the prototype",
        "",
        "| Operation | 61-bit mean (ms) | p=2^127-1 mean (ms) | field-scaling ratio | p=2^127-1 stdev (ms) |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    ratios = []
    for op_name in OPERATIONS:
        mean64 = raw[op_name]["64"]["mean_ms"]
        mean128 = raw[op_name]["128"]["mean_ms"]
        ratio = mean128 / mean64 if mean64 else 0.0
        ratios.append(ratio)
        lines.append(
            f"| `{op_name}` | {mean64:.4f} | {mean128:.4f} | {ratio:.2f} | "
            f"{raw[op_name]['128']['stdev_ms']:.4f} |"
        )

    lines.extend(
        [
            "",
            "Interpretation:",
            "",
            "- These measurements isolate primitive costs on the local Python prototype; distributed transport evidence is reported in the TCP/TLS validation results.",
            "- The ratio column documents primitive-level scaling around the local pipeline over `p=2^127-1`.",
            f"- The arithmetic-heavy primitive ratios range from `{min(ratios):.2f}` to `{max(ratios):.2f}` in this run.",
            "",
            "Raw JSON summary:",
            "",
            "```json",
            json.dumps(raw, indent=2),
            "```",
        ]
    )
    args.summary.write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
