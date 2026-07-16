# Three-VPS Authenticated External-Endpoint Validation

This validation ran the H-SPDZ-Cloud TCP/TLS external-endpoint path on three independent public VPS instances on 2026-07-16.

Topology:

- Edge worker: five transition-source servers.
- Fog worker: three transition-source servers.
- Cloud controller: measurement controller and secure-inference client.

Transport:

- TLS 1.3 with mutual client/server certificate authentication.
- Non-loopback public endpoints were used during measurement.
- Public endpoint addresses are intentionally omitted from this public reproducibility package; host roles and measured network/application results are retained.

Key results:

- D=50 TCP/TLS latency: 229.194 ms mean over 30 runs.
- Edge-to-Fog transition latency: 94.575 ms mean.
- Fog-to-Cloud transition latency: 121.356 ms mean.
- Transition-fault detection: 93.450 ms mean, 30/30 detected.
- Secure WDBC inference: 264.273 ms/sample mean, 100% secure/quantized score match.
