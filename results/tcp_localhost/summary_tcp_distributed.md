# H-SPDZ-Cloud TCP Validation Summary over p=2^127-1

- local TCP servers: `True`
- field prime: `170141183460469231731687303715884105727` (`2^127 - 1`)
- field-element encoding: `16` bytes
- runs: `5`
- configured one-way worker delay: `0.0` ms

## Key Results

- D=50 total latency mean: `83.011` ms
- D=50 Edge-to-Fog TCP transition mean: `49.408` ms
- D=50 Fog-to-Cloud TCP transition mean: `27.055` ms
- D=50 TCP wire payload mean: `7.867` KB
- D=50 model communication mean: `22.969` KB
- fault detection mean: `50.858` ms
- faults detected: `5/5`
- ML secured inference samples: `30`
- ML mean TCP secure inference latency: `78.592` ms
- ML secure/quantized score match rate: `100.00%`
- ML secure/quantized prediction agreement: `100.00%`

## Scope

This validation uses independent TCP party servers for inter-level transitions. It exercises socket serialization, per-party process isolation, and network round trips on localhost. It is a stepping stone toward the same runner on three physical or cloud-separated VMs.
