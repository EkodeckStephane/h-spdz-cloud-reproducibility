# H-SPDZ-Cloud TCP Validation Summary over p=2^127-1

- local TCP servers: `False`
- TLS enabled: `True`
- field prime: `170141183460469231731687303715884105727` (`2^127 - 1`)
- field-element encoding: `16` bytes
- runs: `30`
- configured one-way worker delay: `0.0` ms

## Key Results

- D=50 total latency mean: `229.194` ms
- D=50 Edge-to-Fog TCP transition mean: `94.575` ms
- D=50 Fog-to-Cloud TCP transition mean: `121.356` ms
- D=50 TCP wire payload mean: `7.869` KB
- D=50 model communication mean: `22.969` KB
- fault detection mean: `93.450` ms
- faults detected: `30/30`
- ML secured inference samples: `30`
- ML mean TCP secure inference latency: `264.273` ms
- ML secure/quantized score match rate: `100.00%`
- ML secure/quantized prediction agreement: `100.00%`

## Scope

This validation uses independent TCP party servers for inter-level transitions. It exercises socket serialization, per-party process isolation, mutual TLS transport, and multi-region WAN round trips through the external-server runner.
