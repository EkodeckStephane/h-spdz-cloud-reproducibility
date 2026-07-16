# 61-bit versus 127-bit-prime-field Scaling Micro-benchmark

Configuration:

- runs per operation/field: `30` after `5` warmups
- lower-level parties: `5`
- upper-level parties: `3`
- batch size for batch MAC check: `8`
- small comparison field: `2^61 - 1`
- prototype field: `2^127 - 1` (127-bit binary length, 16-byte encodings)
- commitment backend: BN254 G1 Pedersen helper used by the prototype

| Operation | 61-bit mean (ms) | p=2^127-1 mean (ms) | field-scaling ratio | p=2^127-1 stdev (ms) |
| --- | ---: | ---: | ---: | ---: |
| `mac_check` | 0.0317 | 0.0339 | 1.07 | 0.0095 |
| `batch_mac_check_8` | 0.2759 | 0.2574 | 0.93 | 0.0043 |
| `triple_generation_proxy` | 0.0642 | 0.0671 | 1.05 | 0.0093 |
| `commitment_verification` | 2.7749 | 3.2303 | 1.16 | 0.3828 |
| `inter_level_resharing` | 54.7181 | 63.5375 | 1.16 | 3.7810 |

Interpretation:

- These measurements isolate primitive costs on the local Python prototype; distributed transport evidence is reported in the TCP/TLS validation results.
- The ratio column documents primitive-level scaling around the local pipeline over `p=2^127-1`.
- The arithmetic-heavy primitive ratios range from `0.93` to `1.16` in this run.

Raw JSON summary:

```json
{
  "mac_check": {
    "64": {
      "mean_ms": 0.031716666666666664,
      "stdev_ms": 0.01142103574424248,
      "min_ms": 0.0231,
      "max_ms": 0.069
    },
    "128": {
      "mean_ms": 0.033896666666666665,
      "stdev_ms": 0.009507945255863948,
      "min_ms": 0.024,
      "max_ms": 0.0562
    }
  },
  "batch_mac_check_8": {
    "64": {
      "mean_ms": 0.2759233333333333,
      "stdev_ms": 0.06587312090277235,
      "min_ms": 0.2355,
      "max_ms": 0.4596
    },
    "128": {
      "mean_ms": 0.25737333333333334,
      "stdev_ms": 0.004286058661588136,
      "min_ms": 0.2537,
      "max_ms": 0.27
    }
  },
  "triple_generation_proxy": {
    "64": {
      "mean_ms": 0.06418666666666667,
      "stdev_ms": 0.001340800927221031,
      "min_ms": 0.0631,
      "max_ms": 0.0705
    },
    "128": {
      "mean_ms": 0.06709000000000001,
      "stdev_ms": 0.009309370510960709,
      "min_ms": 0.0632,
      "max_ms": 0.1125
    }
  },
  "commitment_verification": {
    "64": {
      "mean_ms": 2.774913333333333,
      "stdev_ms": 0.32468734641119024,
      "min_ms": 2.4182,
      "max_ms": 3.8067
    },
    "128": {
      "mean_ms": 3.230296666666667,
      "stdev_ms": 0.38281549754538347,
      "min_ms": 2.7858,
      "max_ms": 4.3504
    }
  },
  "inter_level_resharing": {
    "64": {
      "mean_ms": 54.718086666666665,
      "stdev_ms": 1.886886728638644,
      "min_ms": 51.1332,
      "max_ms": 59.1453
    },
    "128": {
      "mean_ms": 63.53753666666667,
      "stdev_ms": 3.780993525013684,
      "min_ms": 58.7417,
      "max_ms": 76.1464
    }
  }
}
```
