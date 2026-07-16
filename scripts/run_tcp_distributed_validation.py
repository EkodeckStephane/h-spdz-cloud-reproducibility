"""TCP-based localhost or external-endpoint validation for H-SPDZ-Cloud.

The script keeps the existing arithmetic prototype over p = 2^127 - 1 unchanged and
replaces inter-level transition workers with independent TCP servers. In local
mode, each Edge/Fog source party runs as a separate process listening on a
different localhost port. The same message format can be reused with independent
physical-host or cloud-instance IPs.
"""

from __future__ import annotations

import argparse
import csv
import json
import socket
import ssl
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from multiprocessing import Process
from pathlib import Path
from typing import Iterable

import numpy as np
from sklearn.datasets import load_breast_cancer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import hspdz_vss  # noqa: E402
from hspdz_cloud_implementation import (  # noqa: E402
    FIELD_BYTES,
    P,
    AuthenticatedShare,
    HSPDZCloud,
    rand_field,
)


BLIND_BYTES = 32
COMMITMENT_BYTES = 64


def write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        return
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def mean(rows: Iterable[dict], key: str) -> float:
    values = [float(row[key]) for row in rows]
    return sum(values) / len(values) if values else 0.0


def _send_json(sock: socket.socket, payload: dict) -> int:
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    sock.sendall(struct.pack("!I", len(data)) + data)
    return 4 + len(data)


def _recv_exact(sock: socket.socket, length: int) -> bytes:
    chunks = []
    remaining = length
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("socket closed while receiving payload")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _recv_json(sock: socket.socket) -> tuple[dict, int]:
    header = _recv_exact(sock, 4)
    length = struct.unpack("!I", header)[0]
    data = _recv_exact(sock, length)
    return json.loads(data.decode("utf-8")), 4 + length


def _handle_transition(task: dict) -> dict:
    start = time.perf_counter()
    source_id = int(task["source_id"])
    n_next = int(task["n_next"])
    share = int(task["share"])
    rho = int(task["rho"])
    corrupt = bool(task.get("corrupt", False))
    delay_ms = float(task.get("delay_ms", 0.0))

    if delay_ms:
        time.sleep(delay_ms / 1000.0)

    source_value = (share + 1) % P if corrupt else share
    subshares = [rand_field() for _ in range(n_next - 1)]
    subshares.append(source_value - sum(subshares))

    blinds = [hspdz_vss.random_blind() for _ in range(n_next - 1)]
    blinds.append((rho - sum(blinds)) % hspdz_vss.curve_order)
    commitments = [hspdz_vss.commit(subshares[j], blinds[j]) for j in range(n_next)]

    if delay_ms:
        time.sleep(delay_ms / 1000.0)

    elapsed_ms = (time.perf_counter() - start) * 1000.0
    return {
        "source_id": source_id,
        "subshares": [int(x) for x in subshares],
        "blinds": [int(x) for x in blinds],
        "commitments_hex": [hspdz_vss.serialize(c).hex() for c in commitments],
        "worker_compute_ms": elapsed_ms,
        "protocol_response_bytes": n_next * (FIELD_BYTES + BLIND_BYTES + COMMITMENT_BYTES),
    }


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


def tcp_party_server(
    host: str,
    port: int,
    tls_certfile: str | None = None,
    tls_keyfile: str | None = None,
    tls_cafile: str | None = None,
    require_client_cert: bool = False,
) -> None:
    tls_context = None
    if tls_certfile:
        if not tls_keyfile:
            raise ValueError("TLS server mode requires --tls-keyfile")
        tls_context = make_server_tls_context(
            tls_certfile,
            tls_keyfile,
            cafile=tls_cafile,
            require_client_cert=require_client_cert,
        )
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
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
                    request, _ = _recv_json(conn)
                except ConnectionError:
                    continue
                action = request.get("action")
                if action == "shutdown":
                    _send_json(conn, {"ok": True})
                    return
                if action != "transition":
                    _send_json(conn, {"ok": False, "error": f"unknown action {action!r}"})
                    continue
                try:
                    response = _handle_transition(request)
                    response["ok"] = True
                except Exception as exc:  # pragma: no cover - returned to controller
                    response = {"ok": False, "error": repr(exc)}
                _send_json(conn, response)


def wait_for_port(host: str, port: int, timeout_s: float = 20.0) -> None:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.25):
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError(f"TCP party server did not start on {host}:{port}")


def start_local_servers(
    host: str,
    ports: list[int],
    tls_certfile: str | None = None,
    tls_keyfile: str | None = None,
    tls_cafile: str | None = None,
    require_client_cert: bool = False,
) -> list[Process]:
    processes = []
    for port in ports:
        proc = Process(
            target=tcp_party_server,
            args=(host, port, tls_certfile, tls_keyfile, tls_cafile, require_client_cert),
            daemon=True,
        )
        proc.start()
        processes.append(proc)
    for port in ports:
        wait_for_port(host, port)
    return processes


def stop_local_servers(
    host: str,
    ports: list[int],
    processes: list[Process],
    tls_context: ssl.SSLContext | None = None,
    tls_server_name: str | None = None,
) -> None:
    for port in ports:
        try:
            with socket.create_connection((host, port), timeout=1.0) as sock:
                conn = tls_context.wrap_socket(
                    sock, server_hostname=tls_server_name or host
                ) if tls_context is not None else sock
                _send_json(conn, {"action": "shutdown"})
                _recv_json(conn)
        except OSError:
            pass
    for proc in processes:
        proc.join(timeout=3.0)
        if proc.is_alive():
            proc.terminate()
            proc.join(timeout=3.0)


def send_transition_task(
    host: str,
    port: int,
    task: dict,
    tls_context: ssl.SSLContext | None = None,
    tls_server_name: str | None = None,
) -> tuple[dict, int]:
    with socket.create_connection((host, port), timeout=30.0) as sock:
        conn = tls_context.wrap_socket(
            sock, server_hostname=tls_server_name or host
        ) if tls_context is not None else sock
        tx = _send_json(conn, task)
        response, rx = _recv_json(conn)
    if not response.get("ok"):
        raise RuntimeError(response.get("error", "TCP party returned failure"))
    return response, tx + rx


def transition_via_tcp(
    proto: HSPDZCloud,
    val: AuthenticatedShare,
    next_level: int,
    commit_data: dict,
    endpoints: list[tuple[str, int]],
    corrupt_sources: set[int] | None = None,
    delay_ms: float = 0.0,
    tls_context: ssl.SSLContext | None = None,
    tls_server_name: str | None = None,
) -> tuple[AuthenticatedShare | None, list[int], dict]:
    corrupt_sources = corrupt_sources or set()
    level = val.level
    n_curr = proto.level_sizes[level]
    n_next = proto.level_sizes[next_level]
    if len(endpoints) < n_curr:
        raise ValueError(f"need {n_curr} endpoints, got {len(endpoints)}")

    start = time.perf_counter()
    tasks = []
    for i in range(n_curr):
        tasks.append(
            {
                "action": "transition",
                "source_id": i,
                "n_next": n_next,
                "share": int(val.shares[i]),
                "rho": int(commit_data["commitment_blinds"][i]),
                "corrupt": i in corrupt_sources,
                "delay_ms": delay_ms,
            }
        )

    responses = []
    tcp_wire_bytes = 0
    with ThreadPoolExecutor(max_workers=n_curr) as executor:
        future_map = {
            executor.submit(
                send_transition_task,
                endpoints[i][0],
                endpoints[i][1],
                tasks[i],
                tls_context,
                tls_server_name,
            ): i
            for i in range(n_curr)
        }
        for future in as_completed(future_map):
            response, wire_bytes = future.result()
            responses.append(response)
            tcp_wire_bytes += wire_bytes

    new_shares = np.zeros(n_next, dtype=object)
    malicious = []
    protocol_response_bytes = 0
    worker_compute_ms = 0.0
    by_source = {int(r["source_id"]): r for r in responses}

    for i in range(n_curr):
        response = by_source[i]
        subshares = [int(x) for x in response["subshares"]]
        blinds = [int(x) for x in response["blinds"]]
        protocol_response_bytes += int(response["protocol_response_bytes"])
        worker_compute_ms = max(worker_compute_ms, float(response["worker_compute_ms"]))

        recomputed = [hspdz_vss.commit(subshares[j], blinds[j]) for j in range(n_next)]
        openings_valid = all(
            hspdz_vss.serialize(recomputed[j]).hex() == response["commitments_hex"][j]
            for j in range(n_next)
        )
        conservation_valid = (
            (sum(subshares) - int(val.shares[i])) % P == 0
            and hspdz_vss.equal(hspdz_vss.combine(recomputed), commit_data["value_commitments"][i])
        )
        if not openings_valid or not conservation_valid:
            malicious.append(i)
        for j in range(n_next):
            new_shares[j] = (new_shares[j] + subshares[j]) % P

    if malicious:
        proto.metrics["fault_detections"] += 1
        proto.metrics["transition_proof_failures"] += len(malicious)
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        return None, malicious, {
            "transition_tcp_ms": elapsed_ms,
            "tcp_wire_bytes": tcp_wire_bytes,
            "protocol_response_bytes": protocol_response_bytes,
            "worker_compute_ms": worker_compute_ms,
        }

    proto.metrics["communication_bytes"] += protocol_response_bytes
    proto.metrics["transitions"] += 1
    mac_shares = proto._authenticate_value_shares(new_shares, next_level)
    transitioned = AuthenticatedShare(new_shares, mac_shares, next_level)
    assert proto.reconstruct(transitioned) == proto.reconstruct(val)
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    return transitioned, [], {
        "transition_tcp_ms": elapsed_ms,
        "tcp_wire_bytes": tcp_wire_bytes,
        "protocol_response_bytes": protocol_response_bytes,
        "worker_compute_ms": worker_compute_ms,
    }


def execute_hierarchical_tcp(
    depth: int,
    edge_endpoints: list[tuple[str, int]],
    fog_endpoints: list[tuple[str, int]],
    delay_ms: float = 0.0,
    n1: int = 5,
    n2: int = 3,
    n3: int = 2,
    tls_context: ssl.SSLContext | None = None,
    tls_server_name: str | None = None,
) -> dict:
    proto = HSPDZCloud([n1, n2, n3])
    x = proto.share_secret(7, 0)
    y = proto.share_secret(3, 0)

    start = time.perf_counter()
    triples = [proto.generate_triple(0) for _ in range(depth)]
    offline_ms = (time.perf_counter() - start) * 1000.0
    offline_bytes = proto.metrics["communication_bytes"]

    start = time.perf_counter()
    current = x
    for idx in range(depth):
        current = proto.multiply(current, y, triples[idx])
    verify_ok = proto.batch_verify([current], 0)
    edge_online_ms = (time.perf_counter() - start) * 1000.0
    online_edge_bytes = proto.metrics["communication_bytes"] - offline_bytes

    start_bytes = proto.metrics["communication_bytes"]
    commit = proto.commit_transition(current, 1)
    fog_result, fog_malicious, fog_net = transition_via_tcp(
        proto,
        current,
        1,
        commit,
        edge_endpoints,
        delay_ms=delay_ms,
        tls_context=tls_context,
        tls_server_name=tls_server_name,
    )
    fog_transition_bytes = proto.metrics["communication_bytes"] - start_bytes

    start_bytes = proto.metrics["communication_bytes"]
    commit2 = proto.commit_transition(fog_result, 2)
    cloud_result, cloud_malicious, cloud_net = transition_via_tcp(
        proto,
        fog_result,
        2,
        commit2,
        fog_endpoints,
        delay_ms=delay_ms,
        tls_context=tls_context,
        tls_server_name=tls_server_name,
    )
    cloud_transition_bytes = proto.metrics["communication_bytes"] - start_bytes

    expected = (7 * pow(3, depth, proto.p)) % proto.p
    correct = (
        verify_ok
        and not fog_malicious
        and not cloud_malicious
        and proto.reconstruct(cloud_result) == expected
    )
    total_ms = offline_ms + edge_online_ms + fog_net["transition_tcp_ms"] + cloud_net["transition_tcp_ms"]

    return {
        "depth": depth,
        "n1": n1,
        "n2": n2,
        "n3": n3,
        "delay_ms": delay_ms,
        "offline_ms": offline_ms,
        "edge_online_ms": edge_online_ms,
        "fog_transition_tcp_ms": fog_net["transition_tcp_ms"],
        "cloud_transition_tcp_ms": cloud_net["transition_tcp_ms"],
        "total_ms": total_ms,
        "offline_bytes": offline_bytes,
        "online_edge_bytes": online_edge_bytes,
        "fog_transition_model_bytes": fog_transition_bytes,
        "cloud_transition_model_bytes": cloud_transition_bytes,
        "fog_transition_tcp_wire_bytes": fog_net["tcp_wire_bytes"],
        "cloud_transition_tcp_wire_bytes": cloud_net["tcp_wire_bytes"],
        "tcp_wire_bytes": fog_net["tcp_wire_bytes"] + cloud_net["tcp_wire_bytes"],
        "total_model_bytes": proto.metrics["communication_bytes"],
        "correct": correct,
    }


def measure_fault_tcp(
    edge_endpoints: list[tuple[str, int]],
    delay_ms: float = 0.0,
    tls_context: ssl.SSLContext | None = None,
    tls_server_name: str | None = None,
) -> dict:
    proto = HSPDZCloud([5, 3, 2])
    shared = proto.share_secret(12345, 0)
    commit = proto.commit_transition(shared, 1)
    start = time.perf_counter()
    transitioned, malicious, net = transition_via_tcp(
        proto,
        shared,
        1,
        commit,
        edge_endpoints,
        corrupt_sources={1},
        delay_ms=delay_ms,
        tls_context=tls_context,
        tls_server_name=tls_server_name,
    )
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    return {
        "n1": 5,
        "n2": 3,
        "delay_ms": delay_ms,
        "detection_ms": elapsed_ms,
        "transition_tcp_ms": net["transition_tcp_ms"],
        "tcp_wire_bytes": net["tcp_wire_bytes"],
        "protocol_response_bytes": net["protocol_response_bytes"],
        "detected": transitioned is None and malicious == [1],
        "malicious": ";".join(str(x) for x in malicious),
    }


def to_signed(value: int, p: int = P) -> int:
    return value - p if value > p // 2 else value


def run_ml_inference_tcp(
    samples: int,
    edge_endpoints: list[tuple[str, int]],
    fog_endpoints: list[tuple[str, int]],
    delay_ms: float = 0.0,
    scale: int = 1000,
    tls_context: ssl.SSLContext | None = None,
    tls_server_name: str | None = None,
) -> tuple[list[dict], dict]:
    dataset = load_breast_cancer()
    x_train, x_test, y_train, y_test = train_test_split(
        dataset.data,
        dataset.target,
        test_size=0.30,
        random_state=42,
        stratify=dataset.target,
    )
    scaler = StandardScaler()
    x_train_scaled = scaler.fit_transform(x_train)
    x_test_scaled = scaler.transform(x_test)

    model = LogisticRegression(max_iter=2000, solver="lbfgs", random_state=42)
    model.fit(x_train_scaled, y_train)
    plaintext_pred = model.predict(x_test_scaled)

    weights_fixed = np.rint(model.coef_[0] * scale).astype(object)
    bias_fixed = int(round(float(model.intercept_[0]) * scale * scale))
    x_fixed = np.rint(x_test_scaled * scale).astype(object)
    quantized_scores = [
        int(sum(int(x_fixed[row, col]) * int(weights_fixed[col]) for col in range(x_fixed.shape[1])) + bias_fixed)
        for row in range(x_fixed.shape[0])
    ]
    quantized_pred = np.array([1 if score >= 0 else 0 for score in quantized_scores])

    secured_count = min(samples, x_fixed.shape[0])
    rows = []
    for sample_idx in range(secured_count):
        proto = HSPDZCloud([5, 3, 2])
        start = time.perf_counter()
        score = proto.share_secret(bias_fixed, 0)
        for feature_idx, weight in enumerate(weights_fixed):
            feature_share = proto.share_secret(int(x_fixed[sample_idx, feature_idx]), 0)
            score = proto.add(score, proto.multiply_by_constant(feature_share, int(weight)))

        edge_ok = proto.batch_verify([score], 0)
        commit = proto.commit_transition(score, 1)
        fog_score, fog_malicious, fog_net = transition_via_tcp(
            proto,
            score,
            1,
            commit,
            edge_endpoints,
            delay_ms=delay_ms,
            tls_context=tls_context,
            tls_server_name=tls_server_name,
        )
        commit2 = proto.commit_transition(fog_score, 2)
        cloud_score, cloud_malicious, cloud_net = transition_via_tcp(
            proto,
            fog_score,
            2,
            commit2,
            fog_endpoints,
            delay_ms=delay_ms,
            tls_context=tls_context,
            tls_server_name=tls_server_name,
        )
        latency_ms = (time.perf_counter() - start) * 1000.0
        cloud_score_signed = to_signed(proto.reconstruct(cloud_score), proto.p)
        secure_pred = 1 if cloud_score_signed >= 0 else 0
        rows.append(
            {
                "sample": sample_idx,
                "true_label": int(y_test[sample_idx]),
                "plaintext_pred": int(plaintext_pred[sample_idx]),
                "quantized_pred": int(quantized_pred[sample_idx]),
                "secure_pred": int(secure_pred),
                "quantized_score": int(quantized_scores[sample_idx]),
                "secure_score": int(cloud_score_signed),
                "latency_ms": latency_ms,
                "tcp_wire_bytes": fog_net["tcp_wire_bytes"] + cloud_net["tcp_wire_bytes"],
                "model_communication_bytes": proto.metrics["communication_bytes"],
                "edge_mac_ok": bool(edge_ok),
                "fog_malicious": ";".join(map(str, fog_malicious)),
                "cloud_malicious": ";".join(map(str, cloud_malicious)),
                "score_matches": cloud_score_signed == int(quantized_scores[sample_idx]),
                "prediction_matches_quantized": secure_pred == int(quantized_pred[sample_idx]),
            }
        )

    summary = {
        "dataset": "Wisconsin Diagnostic Breast Cancer",
        "samples_total": int(dataset.data.shape[0]),
        "features": int(dataset.data.shape[1]),
        "secured_test_samples": secured_count,
        "plaintext_accuracy": float(accuracy_score(y_test, plaintext_pred)),
        "quantized_accuracy": float(accuracy_score(y_test, quantized_pred)),
        "secured_accuracy": accuracy_score(
            [int(row["true_label"]) for row in rows],
            [int(row["secure_pred"]) for row in rows],
        ) if rows else 0.0,
        "secure_quantized_agreement": sum(1 for row in rows if row["prediction_matches_quantized"]) / secured_count if secured_count else 0.0,
        "score_match_rate": sum(1 for row in rows if row["score_matches"]) / secured_count if secured_count else 0.0,
        "mean_latency_ms": mean(rows, "latency_ms"),
        "mean_tcp_wire_kb": mean(rows, "tcp_wire_bytes") / 1024,
        "mean_model_communication_kb": mean(rows, "model_communication_bytes") / 1024,
    }
    return rows, summary


def parse_endpoint_list(raw: str) -> list[tuple[str, int]]:
    endpoints = []
    for item in raw.split(","):
        host, port = item.rsplit(":", 1)
        endpoints.append((host, int(port)))
    return endpoints


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--depth", type=int, default=50)
    parser.add_argument("--ml-samples", type=int, default=30)
    parser.add_argument("--delay-ms", type=float, default=0.0)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "results" / "tcp_localhost")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--edge-ports", default="5611,5612,5613,5614,5615")
    parser.add_argument("--fog-ports", default="5621,5622,5623")
    parser.add_argument("--edge-endpoints", default="")
    parser.add_argument("--fog-endpoints", default="")
    parser.add_argument("--external-servers", action="store_true")
    parser.add_argument("--server-only", action="store_true")
    parser.add_argument("--server-port", type=int, default=0)
    parser.add_argument("--tls", action="store_true")
    parser.add_argument("--tls-certfile", default="")
    parser.add_argument("--tls-keyfile", default="")
    parser.add_argument("--tls-cafile", default="")
    parser.add_argument("--tls-client-certfile", default="")
    parser.add_argument("--tls-client-keyfile", default="")
    parser.add_argument("--tls-require-client-cert", action="store_true")
    parser.add_argument("--tls-server-name", default="")
    parser.add_argument("--insecure-tls-for-test", action="store_true")
    args = parser.parse_args()

    if args.server_only:
        if args.server_port <= 0:
            raise ValueError("--server-only requires --server-port")
        tcp_party_server(
            args.host,
            args.server_port,
            tls_certfile=args.tls_certfile or None,
            tls_keyfile=args.tls_keyfile or None,
            tls_cafile=args.tls_cafile or None,
            require_client_cert=args.tls_require_client_cert,
        )
        return

    client_tls_context = None
    if args.tls:
        client_tls_context = make_client_tls_context(
            args.tls_cafile or None,
            certfile=args.tls_client_certfile or None,
            keyfile=args.tls_client_keyfile or None,
            insecure_tls_for_test=args.insecure_tls_for_test,
        )
    tls_server_name = args.tls_server_name or None

    if args.external_servers:
        if not args.edge_endpoints or not args.fog_endpoints:
            raise ValueError("--external-servers requires --edge-endpoints and --fog-endpoints")
        edge_endpoints = parse_endpoint_list(args.edge_endpoints)
        fog_endpoints = parse_endpoint_list(args.fog_endpoints)
        all_processes: list[Process] = []
        all_ports: list[int] = []
    else:
        if args.tls and (not args.tls_certfile or not args.tls_keyfile):
            raise ValueError("local TLS mode requires --tls-certfile and --tls-keyfile")
        edge_ports = [int(x) for x in args.edge_ports.split(",")]
        fog_ports = [int(x) for x in args.fog_ports.split(",")]
        all_ports = edge_ports + fog_ports
        all_processes = start_local_servers(
            args.host,
            all_ports,
            tls_certfile=args.tls_certfile or None,
            tls_keyfile=args.tls_keyfile or None,
            tls_cafile=args.tls_cafile or None,
            require_client_cert=args.tls_require_client_cert,
        )
        edge_endpoints = [(args.host, port) for port in edge_ports]
        fog_endpoints = [(args.host, port) for port in fog_ports]

    out_dir = args.output_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        pipeline_rows = []
        for run in range(args.runs):
            row = execute_hierarchical_tcp(
                depth=args.depth,
                edge_endpoints=edge_endpoints,
                fog_endpoints=fog_endpoints,
                delay_ms=args.delay_ms,
                tls_context=client_tls_context,
                tls_server_name=tls_server_name,
            )
            row["run"] = run
            pipeline_rows.append(row)
        write_csv(out_dir / "tcp_pipeline_128bit.csv", pipeline_rows)

        fault_rows = []
        for run in range(args.runs):
            row = measure_fault_tcp(
                edge_endpoints=edge_endpoints,
                delay_ms=args.delay_ms,
                tls_context=client_tls_context,
                tls_server_name=tls_server_name,
            )
            row["run"] = run
            fault_rows.append(row)
        write_csv(out_dir / "tcp_fault_detection_128bit.csv", fault_rows)

        ml_rows, ml_summary = run_ml_inference_tcp(
            samples=args.ml_samples,
            edge_endpoints=edge_endpoints,
            fog_endpoints=fog_endpoints,
            delay_ms=args.delay_ms,
            tls_context=client_tls_context,
            tls_server_name=tls_server_name,
        )
        write_csv(out_dir / "tcp_ml_inference_breast_cancer_128bit.csv", ml_rows)
        write_csv(out_dir / "tcp_ml_inference_breast_cancer_summary.csv", [ml_summary])

        grouped_50 = pipeline_rows
        summary_lines = [
            "# H-SPDZ-Cloud TCP Validation Summary over p=2^127-1",
            "",
            f"- local TCP servers: `{not args.external_servers}`",
            f"- TLS enabled: `{args.tls}`",
            f"- field prime: `{P}` (`2^127 - 1`)",
            f"- field-element encoding: `{FIELD_BYTES}` bytes",
            f"- runs: `{args.runs}`",
            f"- configured one-way worker delay: `{args.delay_ms}` ms",
            "",
            "## Key Results",
            "",
            f"- D={args.depth} total latency mean: `{mean(grouped_50, 'total_ms'):.3f}` ms",
            f"- D={args.depth} Edge-to-Fog TCP transition mean: `{mean(grouped_50, 'fog_transition_tcp_ms'):.3f}` ms",
            f"- D={args.depth} Fog-to-Cloud TCP transition mean: `{mean(grouped_50, 'cloud_transition_tcp_ms'):.3f}` ms",
            f"- D={args.depth} TCP wire payload mean: `{mean(grouped_50, 'tcp_wire_bytes') / 1024:.3f}` KB",
            f"- D={args.depth} model communication mean: `{mean(grouped_50, 'total_model_bytes') / 1024:.3f}` KB",
            f"- fault detection mean: `{mean(fault_rows, 'detection_ms'):.3f}` ms",
            f"- faults detected: `{sum(1 for r in fault_rows if str(r['detected']) == 'True')}/{len(fault_rows)}`",
            f"- ML secured inference samples: `{ml_summary['secured_test_samples']}`",
            f"- ML mean TCP secure inference latency: `{ml_summary['mean_latency_ms']:.3f}` ms",
            f"- ML secure/quantized score match rate: `{100 * ml_summary['score_match_rate']:.2f}%`",
            f"- ML secure/quantized prediction agreement: `{100 * ml_summary['secure_quantized_agreement']:.2f}%`",
            "",
            "## Scope",
            "",
            "This validation uses independent TCP party servers for inter-level transitions. "
            "It exercises socket serialization, per-party process isolation, and network "
            "round trips, mutual TLS transport, and external-endpoint execution through "
            "physical or cloud-separated VMs.",
            "",
        ]
        (out_dir / "summary_tcp_distributed.md").write_text("\n".join(summary_lines), encoding="utf-8")
        print("\n".join(summary_lines))
    finally:
        if not args.external_servers:
            stop_local_servers(
                args.host,
                all_ports,
                all_processes,
                tls_context=client_tls_context,
                tls_server_name=tls_server_name,
            )


if __name__ == "__main__":
    main()
