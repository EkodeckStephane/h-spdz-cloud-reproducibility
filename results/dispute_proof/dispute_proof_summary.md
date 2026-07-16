# Dispute-Proof Benchmark

Status: MEASURED local prototype benchmark.

Configuration:

- command: `python scripts/benchmark_dispute_proof.py`
- runs: `30` after `5` warmups
- lower-level parties: `5`
- upper-level receivers: `3`
- proof system: `Sigma/Schnorr Fiat-Shamir over BN254 prototype Pedersen commitments`
- transport evidence: application-level Schnorr SignedTranscript objects

| Metric | Mean | Std. dev. |
| --- | ---: | ---: |
| proof generation (ms) | 104.074 | 5.058 |
| proof verification (ms) | 278.495 | 12.880 |
| proof size (bytes) | 1291.5 | 1.7 |
| signed transcript bytes | 2230.2 | 0.9 |
| generation peak memory (MB) | 0.0065 | 0.0000 |
| verification peak memory (MB) | 0.1156 | 0.0007 |

Raw CSV: `results/dispute_proof/dispute_proof_results.csv`

Interpretation:

- These are measured local prototype costs; optimized native cryptographic backends are a follow-up engineering target.
- The proof hides transition sub-share values while proving consistency of the Pedersen transition commitments.
- SignedTranscript objects bind the proof to transferable application-level evidence; TLS provides authenticated transport for the TCP/TLS runs.
