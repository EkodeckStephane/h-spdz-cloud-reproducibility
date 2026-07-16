# H-SPDZ-Cloud Local Pipeline Summary over p=2^127-1

- field prime: `170141183460469231731687303715884105727` (`2^127 - 1`)
- field-element encoding: `16` bytes
- runs per repeated configuration: `5`

## Key Results

- D=50 total latency mean: `696.201` ms
- D=50 communication mean: `22.969` KB
- n1=5 transition fault-detection mean: `3066.827` ms
- online communication reduction vs local flat baseline: `31.43%`
- total communication reduction vs local flat baseline: `42.35%`
- ML dataset: `Wisconsin Diagnostic Breast Cancer` (569 samples, 30 features)
- ML plaintext test accuracy: `98.83%`
- ML quantized test accuracy: `98.83%`
- ML secured inference samples: `30`
- ML secure accuracy on secured subset: `96.67%`
- ML secure/quantized prediction agreement: `100.00%`
- ML secure/quantized score match rate: `100.00%`
- ML mean secure inference latency: `690.164` ms
- ML mean secure inference communication: `3.438` KB

## Scope

These are full local-pipeline measurements over p=2^127-1, represented with 16-byte field-element encodings, for the executable prototype in this repository. The companion three-VPS results cover authenticated multi-region WAN transport validation.
