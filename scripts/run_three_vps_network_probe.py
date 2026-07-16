"""Three-VPS network probe with optional TLS 1.3.

This script is intentionally separate from the H-SPDZ-Cloud workload runner. It
measures the network layer used before external-endpoint application benchmarks:
TCP connect time, TLS handshake time, RTT, payload echo throughput, failures,
jitter, p95, IQR, and 95% confidence intervals.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import socket
import ssl
import statistics
import struct
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


def send_frame(sock: socket.socket, payload: bytes) -> None:
    sock.sendall(struct.pack("!I", len(payload)) + payload)


def recv_exact(sock: socket.socket, length: int) -> bytes:
    chunks = []
    remaining = length
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("socket closed while reading frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def recv_frame(sock: socket.socket) -> bytes:
    header = recv_exact(sock, 4)
    length = struct.unpack("!I", header)[0]
    return recv_exact(sock, length)


def make_server_tls_context(
    certfile: str,
    keyfile: str,
    cafile: str | None = None,
    require_client_cert: bool = False,
) -> ssl.SSLContext:
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    if cafile:
        context.load_verify_locations(cafile=cafile)
    context.verify_mode = ssl.CERT_REQUIRED if require_client_cert else ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    return context


def make_client_tls_context(
    cafile: str | None,
    certfile: str | None = None,
    keyfile: str | None = None,
    insecure_tls_for_test: bool = False,
) -> ssl.SSLContext:
    if insecure_tls_for_test:
        context = ssl._create_unverified_context()
    else:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=cafile)
    if certfile:
        context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    return context


def run_server(args: argparse.Namespace) -> None:
    tls_context = None
    if args.tls_certfile:
        tls_context = make_server_tls_context(
            args.tls_certfile,
            args.tls_keyfile,
            cafile=args.tls_cafile or None,
            require_client_cert=args.tls_require_client_cert,
        )

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((args.host, args.port))
        server.listen()
        while True:
            raw_conn, _ = server.accept()
            conn = raw_conn
            try:
                if tls_context is not None:
                    conn = tls_context.wrap_socket(raw_conn, server_side=True)
            except ssl.SSLError:
                raw_conn.close()
                continue
            with conn:
                try:
                    payload = recv_frame(conn)
                except ConnectionError:
                    continue
                if payload == b"shutdown":
                    send_frame(conn, b"ok")
                    return
                send_frame(conn, payload)


def parse_targets(raw: str) -> list[tuple[str, str, int]]:
    targets = []
    for item in raw.split(","):
        if not item:
            continue
        name, endpoint = item.split("=", 1)
        host, port = endpoint.rsplit(":", 1)
        targets.append((name, host, int(port)))
    return targets


def is_loopback_host(host: str) -> bool:
    if host.lower() in {"localhost"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return False
    for info in infos:
        try:
            if ipaddress.ip_address(info[4][0]).is_loopback:
                return True
        except ValueError:
            continue
    return False


def probe_once(
    target_name: str,
    host: str,
    port: int,
    payload: bytes,
    timeout_s: float,
    tls_context: ssl.SSLContext | None,
    tls_server_name: str | None,
) -> dict:
    started = time.perf_counter_ns()
    with socket.create_connection((host, port), timeout=timeout_s) as raw_sock:
        connect_ms = (time.perf_counter_ns() - started) / 1_000_000
        sock = raw_sock
        tls_ms = 0.0
        tls_cipher = ""
        if tls_context is not None:
            tls_start = time.perf_counter_ns()
            sock = tls_context.wrap_socket(raw_sock, server_hostname=tls_server_name or host)
            tls_ms = (time.perf_counter_ns() - tls_start) / 1_000_000
            tls_cipher = "/".join(str(x) for x in sock.cipher())

        ping_start = time.perf_counter_ns()
        send_frame(sock, b"x")
        pong = recv_frame(sock)
        rtt_ms = (time.perf_counter_ns() - ping_start) / 1_000_000
        if pong != b"x":
            raise AssertionError("probe server returned unexpected ping payload")

    with socket.create_connection((host, port), timeout=timeout_s) as raw_sock:
        sock = raw_sock
        if tls_context is not None:
            sock = tls_context.wrap_socket(raw_sock, server_hostname=tls_server_name or host)
        bw_start = time.perf_counter_ns()
        send_frame(sock, payload)
        echoed = recv_frame(sock)
        elapsed_s = (time.perf_counter_ns() - bw_start) / 1_000_000_000
        if hashlib.sha256(echoed).digest() != hashlib.sha256(payload).digest():
            raise AssertionError("probe server returned unexpected payload")
        bandwidth_mbps = (2 * len(payload) * 8) / (elapsed_s * 1_000_000)

    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "target": target_name,
        "host": host,
        "port": port,
        "tcp_connect_ms": connect_ms,
        "tls_handshake_ms": tls_ms,
        "rtt_ms": rtt_ms,
        "payload_bytes": len(payload),
        "echo_bandwidth_mbps": bandwidth_mbps,
        "tls_cipher": tls_cipher,
        "ok": True,
        "error": "",
    }


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = (len(ordered) - 1) * pct
    low = int(index)
    high = min(low + 1, len(ordered) - 1)
    weight = index - low
    return ordered[low] * (1 - weight) + ordered[high] * weight


def summarize(rows: list[dict], key: str) -> dict:
    values = [float(row[key]) for row in rows if str(row.get("ok")) == "True"]
    if not values:
        return {f"{key}_{suffix}": 0.0 for suffix in ("mean", "median", "stdev", "iqr", "p95", "ci95")}
    stdev = statistics.stdev(values) if len(values) > 1 else 0.0
    return {
        f"{key}_mean": statistics.fmean(values),
        f"{key}_median": statistics.median(values),
        f"{key}_stdev": stdev,
        f"{key}_iqr": percentile(values, 0.75) - percentile(values, 0.25),
        f"{key}_p95": percentile(values, 0.95),
        f"{key}_ci95": 1.96 * stdev / (len(values) ** 0.5) if len(values) > 1 else 0.0,
    }


def run_probe(args: argparse.Namespace) -> None:
    targets = parse_targets(args.targets)
    if args.require_non_loopback:
        loopback = [f"{name}={host}:{port}" for name, host, port in targets if is_loopback_host(host)]
        if loopback:
            raise ValueError(
                "Non-loopback mode rejects loopback targets: " + ", ".join(loopback)
            )

    tls_context = None
    if args.tls:
        tls_context = make_client_tls_context(
            args.tls_cafile or None,
            certfile=args.tls_client_certfile or None,
            keyfile=args.tls_client_keyfile or None,
            insecure_tls_for_test=args.insecure_tls_for_test,
        )

    payload = bytes((i % 251 for i in range(args.payload_bytes)))
    rows = []
    for _ in range(args.warmups):
        for name, host, port in targets:
            try:
                probe_once(name, host, port, payload, args.timeout_s, tls_context, args.tls_server_name or None)
            except Exception:
                pass

    for run in range(args.runs):
        for name, host, port in targets:
            try:
                row = probe_once(
                    name,
                    host,
                    port,
                    payload,
                    args.timeout_s,
                    tls_context,
                    args.tls_server_name or None,
                )
            except Exception as exc:
                row = {
                    "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                    "target": name,
                    "host": host,
                    "port": port,
                    "tcp_connect_ms": 0.0,
                    "tls_handshake_ms": 0.0,
                    "rtt_ms": 0.0,
                    "payload_bytes": args.payload_bytes,
                    "echo_bandwidth_mbps": 0.0,
                    "tls_cipher": "",
                    "ok": False,
                    "error": repr(exc),
                }
            row["run"] = run
            rows.append(row)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    raw_path = args.output_dir / "three_vps_network_probe_raw.csv"
    with raw_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    summary_rows = []
    for name, host, port in targets:
        target_rows = [row for row in rows if row["target"] == name]
        ok_count = sum(1 for row in target_rows if str(row["ok"]) == "True")
        summary = {
            "target": name,
            "host": host,
            "port": port,
            "runs": len(target_rows),
            "ok": ok_count,
            "failures": len(target_rows) - ok_count,
            "loss_rate": (len(target_rows) - ok_count) / len(target_rows) if target_rows else 0.0,
            "payload_bytes": args.payload_bytes,
            "tls_enabled": args.tls,
        }
        for metric in ("tcp_connect_ms", "tls_handshake_ms", "rtt_ms", "echo_bandwidth_mbps"):
            summary.update(summarize(target_rows, metric))
        summary_rows.append(summary)

    summary_path = args.output_dir / "three_vps_network_probe_summary.csv"
    with summary_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(summary_rows[0].keys()))
        writer.writeheader()
        writer.writerows(summary_rows)

    lines = [
        "# Three-VPS Network Probe Summary",
        "",
        f"- command: `python {' '.join(sys.argv)}`",
        f"- runs: `{args.runs}` after `{args.warmups}` warmups",
        f"- TLS enabled: `{args.tls}`",
        f"- payload bytes: `{args.payload_bytes}`",
        f"- raw CSV: `{raw_path.as_posix()}`",
        f"- summary CSV: `{summary_path.as_posix()}`",
        "",
        "| Target | RTT mean (ms) | RTT p95 (ms) | Jitter/stdev (ms) | Loss | Echo bandwidth mean (Mbps) | TLS handshake mean (ms) |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in summary_rows:
        lines.append(
            f"| {row['target']} | {row['rtt_ms_mean']:.3f} | {row['rtt_ms_p95']:.3f} | "
            f"{row['rtt_ms_stdev']:.3f} | {100 * row['loss_rate']:.2f}% | "
            f"{row['echo_bandwidth_mbps_mean']:.3f} | {row['tls_handshake_ms_mean']:.3f} |"
        )
    (args.output_dir / "three_vps_network_probe_summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="mode", required=True)

    server = subparsers.add_parser("server")
    server.add_argument("--host", default="0.0.0.0")
    server.add_argument("--port", type=int, required=True)
    server.add_argument("--tls-certfile", default="")
    server.add_argument("--tls-keyfile", default="")
    server.add_argument("--tls-cafile", default="")
    server.add_argument("--tls-require-client-cert", action="store_true")

    probe = subparsers.add_parser("probe")
    probe.add_argument("--targets", required=True, help="comma list like edge=10.0.1.10:5700,fog=10.0.2.10:5700")
    probe.add_argument("--runs", type=int, default=30)
    probe.add_argument("--warmups", type=int, default=5)
    probe.add_argument("--payload-bytes", type=int, default=262144)
    probe.add_argument("--timeout-s", type=float, default=10.0)
    probe.add_argument("--output-dir", type=Path, default=Path("results/three_vps_network_probe"))
    probe.add_argument("--tls", action="store_true")
    probe.add_argument("--tls-cafile", default="")
    probe.add_argument("--tls-client-certfile", default="")
    probe.add_argument("--tls-client-keyfile", default="")
    probe.add_argument("--tls-server-name", default="")
    probe.add_argument("--insecure-tls-for-test", action="store_true")
    probe.add_argument("--require-non-loopback", action="store_true")

    args = parser.parse_args()
    if args.mode == "server":
        run_server(args)
    else:
        run_probe(args)


if __name__ == "__main__":
    main()
