"""
Pedersen-style commitment and verifiable resharing helpers for H-SPDZ-Cloud.

The implementation uses py_ecc's optimized BN254 G1 group. It is intended for
prototype validation and tests; deployment code should still pin audited
serialization, transcript domain separation, and a reviewed VSS library.
"""

from __future__ import annotations

import hashlib
import secrets
from typing import Iterable, Tuple

from py_ecc.optimized_bn128 import G1, add, curve_order, is_on_curve, multiply, normalize, Z1
from py_ecc.optimized_bn128.optimized_curve import b

Scalar = int
Commitment = Tuple


def _hash_to_scalar(label: bytes) -> Scalar:
    digest = hashlib.sha256(label).digest()
    value = int.from_bytes(digest, "big") % curve_order
    return value or 1


H = multiply(G1, _hash_to_scalar(b"H-SPDZ-Cloud Pedersen H generator v1"))
WINDOW_BITS = 4
WINDOW_SIZE = 1 << WINDOW_BITS


def _build_fixed_base_table(base: Commitment) -> list[list[Commitment]]:
    table = []
    current = base
    windows = (curve_order.bit_length() + WINDOW_BITS - 1) // WINDOW_BITS
    for _ in range(windows):
        multiples = [Z1]
        acc = Z1
        for _ in range(1, WINDOW_SIZE):
            acc = add(acc, current)
            multiples.append(acc)
        table.append(multiples)
        for _ in range(WINDOW_BITS):
            current = add(current, current)
    return table


_G1_FIXED_TABLE = _build_fixed_base_table(G1)
_H_FIXED_TABLE = _build_fixed_base_table(H)


def _fixed_base_multiply(scalar: int, table: list[list[Commitment]]) -> Commitment:
    scalar %= curve_order
    acc = Z1
    index = 0
    while scalar:
        digit = scalar & (WINDOW_SIZE - 1)
        if digit:
            acc = add(acc, table[index][digit])
        scalar >>= WINDOW_BITS
        index += 1
    return acc


def random_blind() -> Scalar:
    return secrets.randbelow(curve_order - 1) + 1


def scalar_base_multiply(scalar: int) -> Commitment:
    """Multiply the canonical G1 generator by a scalar."""
    return _fixed_base_multiply(int(scalar), _G1_FIXED_TABLE)


def scalar_multiply(point: Commitment, scalar: int) -> Commitment:
    """Multiply an arbitrary commitment point by a scalar."""
    return multiply(point, int(scalar) % curve_order)


def point_add(left: Commitment, right: Commitment) -> Commitment:
    """Add two commitment points."""
    return add(left, right)


def commit(value: int, blind: int) -> Commitment:
    point = add(
        _fixed_base_multiply(int(value), _G1_FIXED_TABLE),
        _fixed_base_multiply(int(blind), _H_FIXED_TABLE),
    )
    if not is_on_curve(point, b):
        raise ValueError("invalid commitment point")
    return point


def identity() -> Commitment:
    return Z1


def combine(commitments: Iterable[Commitment]) -> Commitment:
    acc = Z1
    for c in commitments:
        acc = add(acc, c)
    return acc


def equal(left: Commitment, right: Commitment) -> bool:
    return normalize(left) == normalize(right)


def serialize(commitment: Commitment) -> bytes:
    x, y = normalize(commitment)
    return int(x).to_bytes(32, "big") + int(y).to_bytes(32, "big")
