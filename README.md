# H-SPDZ-Cloud Reproducibility Package

This repository contains the public reproducibility package for:

**H-SPDZ-Cloud: A Formal Prototype for Hierarchical Authenticated MPC in Edge--Fog--Cloud Architectures**

The package supports the study's prototype claims with source code, tests,
measurement scripts, measured summaries, and figures.

## Contents

- `hspdz_cloud_implementation.py`, `hspdz_vss.py`, `hspdz_dispute.py`: Python prototype implementation.
- `tests/`: regression tests for batch MAC verification, VSS commitments, and privacy-preserving dispute proofs.
- `scripts/`: measurement runners for the local 127-bit-prime pipeline, local TCP validation, external-endpoint TCP/TLS validation, and network probing.
- `results/local_127bit/`: local full-pipeline measurements over `p = 2^127 - 1`.
- `results/tcp_localhost/`: localhost TCP validation measurements with independent transition servers.
- `results/three_vps/`: authenticated three-VPS TCP/TLS validation summaries and sanitized host characteristics.
- `results/dispute_proof/`: Sigma/Schnorr dispute-proof benchmark results.
- `results/security_scaling/`: 61-bit versus 127-bit-prime micro-benchmark results.
- `benchmarks/mpspdz_programs/`: small MP-SPDZ reference workloads.
- `figures/`: figures generated from the measured outputs.

## Validation Notes

The Python prototype reproduces the H-SPDZ-Cloud online arithmetic, transition
verification, masked MAC checks, privacy-preserving dispute-proof path, secure
inference workflow, and TCP/TLS runners used for the reported measurements.

The offline triples in this package are local reproducibility triples for
testing the online and transition paths. The MP-SPDZ programs are comparable
reference workloads, matching the manuscript's use of MP-SPDZ as a reference
execution alongside the Python prototype measurements.

The three-VPS material records the authenticated multi-region WAN
external-endpoint execution conducted on 16 July 2026 with mutual TLS 1.3 and
sanitized host metadata. Follow-up engineering work will add repeated WAN
campaigns, integrated MP-SPDZ preprocessing, and larger deployment automation.

## Quick Start

Create and activate a Python environment, then install dependencies:

```bash
python -m pip install -r requirements.txt
```

Run core regression tests:

```bash
python tests/test_gap0_batch_verify.py
python tests/test_vss_commitments.py
python tests/test_dispute_proof.py
```

Run the local 127-bit-prime pipeline:

```bash
python scripts/run_128bit_pipeline.py --output-dir results/local_127bit_rerun
```

Run the localhost TCP validation:

```bash
python scripts/run_tcp_distributed_validation.py --runs 5 --ml-samples 30 --output-dir results/tcp_localhost_rerun
```

## Key Measured Results

- Local 127-bit-prime pipeline, `D=50`: `696.201 ms` mean latency.
- Communication reduction versus internal flat Python baseline: `31.43%` online and `42.35%` total communication.
- Local fault localization, `n1=5`: `3066.827 ms` mean.
- Localhost TCP validation, `D=50`: `83.011 ms` mean latency, `5/5` injected faults detected.
- Three-VPS TCP/TLS validation, `D=50`: `229.194 ms` mean latency over 30 runs.
- Three-VPS transition fault detection: `93.450 ms` mean, `30/30` detected.
- Three-VPS secure WDBC inference: `264.273 ms/sample` mean, `100%` secure/quantized score match.

## Data and Privacy Notes

The public three-VPS package retains role-level host characteristics and
measured results with sensitive operational material removed from the release.

## Citation

Please cite the associated publication and the archived software release
associated with this repository. A `CITATION.cff` file is included for software
citation metadata.
