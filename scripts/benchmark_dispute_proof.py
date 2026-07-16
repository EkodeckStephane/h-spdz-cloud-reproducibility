"""Measure the SignedTranscript and Sigma/Schnorr dispute-proof path."""

from __future__ import annotations

import argparse
import csv
import json
import secrets
import statistics
import sys
import time
import tracemalloc
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import hspdz_dispute  # noqa: E402
import hspdz_vss  # noqa: E402
from hspdz_cloud_implementation import HSPDZCloud, rand_commit_blind, rand_field  # noqa: E402


def mean(rows: list[dict], key: str) -> float:
    return statistics.fmean(float(row[key]) for row in rows)


def stdev(rows: list[dict], key: str) -> float:
    values = [float(row[key]) for row in rows]
    return statistics.stdev(values) if len(values) > 1 else 0.0


def write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def make_statement(n_edge: int, n_fog: int, source_id: int):
    proto = HSPDZCloud([n_edge, n_fog, 2])
    shared = proto.share_secret(rand_field(), 0)
    commit_data = proto.commit_transition(shared, 1)
    source_value = int(shared.shares[source_id])
    source_blind = int(commit_data["commitment_blinds"][source_id])

    subshares = [rand_field() for _ in range(n_fog - 1)]
    subshares.append(source_value - sum(subshares))
    sub_blinds = [rand_commit_blind() for _ in range(n_fog - 1)]
    sub_blinds.append((source_blind - sum(sub_blinds)) % hspdz_vss.curve_order)
    sub_commitments = [
        hspdz_vss.commit(subshares[j], sub_blinds[j]) for j in range(n_fog)
    ]
    context = {
        "session_id": commit_data["session_id"],
        "level_id": 0,
        "next_level": 1,
        "transition_id": commit_data["transition_id"],
        "source_id": source_id,
        "n_next": n_fog,
    }
    source_party = proto.levels[0][source_id]
    transcripts = []
    for j, commitment in enumerate(sub_commitments):
        transcripts.append(
            hspdz_dispute.create_signed_transcript(
                signing_key=source_party.signing_key,
                session_id=commit_data["session_id"],
                level_id=0,
                transition_id=commit_data["transition_id"],
                sender_id=source_id,
                receiver_id=j,
                sequence_number=j,
                commitment_id=f"{commit_data['transition_id']}:src{source_id}:recv{j}",
                payload_digest=hspdz_dispute.digest_transition_payload(
                    receiver_id=j,
                    commitment=commitment,
                ),
            )
        )
    return {
        "context": context,
        "source_commitment": commit_data["value_commitments"][source_id],
        "source_value": source_value,
        "source_blind": source_blind,
        "subshares": subshares,
        "sub_blinds": sub_blinds,
        "sub_commitments": sub_commitments,
        "transcripts": transcripts,
    }


def measure_once(args: argparse.Namespace, run_index: int, command: str) -> dict:
    statement = make_statement(
        args.n_edge,
        args.n_fog,
        source_id=run_index % args.n_edge,
    )

    tracemalloc.start()
    gen_start = time.perf_counter_ns()
    proof = hspdz_dispute.prove_transition_consistency(
        context=statement["context"],
        source_commitment=statement["source_commitment"],
        sub_commitments=statement["sub_commitments"],
        source_value=statement["source_value"],
        source_blind=statement["source_blind"],
        subshares=statement["subshares"],
        sub_blinds=statement["sub_blinds"],
        signed_transcripts=statement["transcripts"],
    )
    gen_ms = (time.perf_counter_ns() - gen_start) / 1_000_000
    _, gen_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    tracemalloc.start()
    verify_start = time.perf_counter_ns()
    verified = hspdz_dispute.verify_transition_consistency_proof(
        context=statement["context"],
        source_commitment=statement["source_commitment"],
        sub_commitments=statement["sub_commitments"],
        signed_transcripts=statement["transcripts"],
        proof=proof,
    )
    verify_ms = (time.perf_counter_ns() - verify_start) / 1_000_000
    _, verify_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    transcript_bytes = sum(
        len(json.dumps(t.to_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8"))
        for t in statement["transcripts"]
    )
    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "run_id": secrets.token_hex(8),
        "command": command,
        "run_index": run_index,
        "n_edge": args.n_edge,
        "n_fog": args.n_fog,
        "proof_system": "Sigma/Schnorr Fiat-Shamir over BN254 prototype Pedersen commitments",
        "proof_bytes": proof.encoded_size(),
        "signed_transcript_count": len(statement["transcripts"]),
        "signed_transcript_bytes": transcript_bytes,
        "prove_ms": gen_ms,
        "verify_ms": verify_ms,
        "prove_peak_memory_mb": gen_peak / (1024 * 1024),
        "verify_peak_memory_mb": verify_peak / (1024 * 1024),
        "verified": verified,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=30)
    parser.add_argument("--warmups", type=int, default=5)
    parser.add_argument("--n-edge", type=int, default=5)
    parser.add_argument("--n-fog", type=int, default=3)
    parser.add_argument("--output", type=Path, default=Path("results/dispute_proof/dispute_proof_results.csv"))
    parser.add_argument("--summary", type=Path, default=Path("results/dispute_proof/dispute_proof_summary.md"))
    args = parser.parse_args()
    command = "python " + " ".join(sys.argv)

    for idx in range(args.warmups):
        measure_once(args, idx, command)

    rows = [measure_once(args, idx, command) for idx in range(args.runs)]
    if not all(row["verified"] for row in rows):
        raise AssertionError("at least one dispute proof failed verification")
    write_csv(args.output, rows)
    args.summary.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        "# Dispute-Proof Benchmark",
        "",
        "Status: MEASURED local prototype benchmark.",
        "",
        "Configuration:",
        "",
        f"- command: `{command}`",
        f"- runs: `{args.runs}` after `{args.warmups}` warmups",
        f"- lower-level parties: `{args.n_edge}`",
        f"- upper-level receivers: `{args.n_fog}`",
        "- proof system: `Sigma/Schnorr Fiat-Shamir over BN254 prototype Pedersen commitments`",
        "- transport evidence: application-level Schnorr SignedTranscript objects",
        "",
        "| Metric | Mean | Std. dev. |",
        "| --- | ---: | ---: |",
        f"| proof generation (ms) | {mean(rows, 'prove_ms'):.3f} | {stdev(rows, 'prove_ms'):.3f} |",
        f"| proof verification (ms) | {mean(rows, 'verify_ms'):.3f} | {stdev(rows, 'verify_ms'):.3f} |",
        f"| proof size (bytes) | {mean(rows, 'proof_bytes'):.1f} | {stdev(rows, 'proof_bytes'):.1f} |",
        f"| signed transcript bytes | {mean(rows, 'signed_transcript_bytes'):.1f} | {stdev(rows, 'signed_transcript_bytes'):.1f} |",
        f"| generation peak memory (MB) | {mean(rows, 'prove_peak_memory_mb'):.4f} | {stdev(rows, 'prove_peak_memory_mb'):.4f} |",
        f"| verification peak memory (MB) | {mean(rows, 'verify_peak_memory_mb'):.4f} | {stdev(rows, 'verify_peak_memory_mb'):.4f} |",
        "",
        f"Raw CSV: `{args.output.as_posix()}`",
        "",
        "Interpretation:",
        "",
        "- These are measured local prototype costs; optimized native cryptographic backends are a follow-up engineering target.",
        "- The proof hides transition sub-share values while proving consistency of the Pedersen transition commitments.",
        "- SignedTranscript objects bind the proof to transferable application-level evidence; TLS provides authenticated transport for the TCP/TLS runs.",
    ]
    args.summary.write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
