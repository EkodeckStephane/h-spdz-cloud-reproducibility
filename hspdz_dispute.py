"""
Privacy-preserving dispute evidence for the H-SPDZ-Cloud prototype.

This module implements the privacy-preserving dispute path: application
SignedTranscript evidence plus a non-interactive Sigma/Schnorr proof for the
linear Pedersen transition relation. This compact prototype uses the existing
BN254 helper for reproducible validation; audited signature and VSS backends are
deployment engineering targets.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import asdict, dataclass
from typing import Iterable

import hspdz_vss

SCALAR_ORDER = hspdz_vss.curve_order


def _scalar(value: int) -> int:
    return int(value) % SCALAR_ORDER


def _point_hex(point: hspdz_vss.Commitment) -> str:
    return hspdz_vss.serialize(point).hex()


def _canonical_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _hash_scalar(*parts: bytes) -> int:
    h = hashlib.sha256()
    for part in parts:
        h.update(len(part).to_bytes(8, "big"))
        h.update(part)
    return int.from_bytes(h.digest(), "big") % SCALAR_ORDER


def _hash_hex(*parts: bytes) -> str:
    h = hashlib.sha256()
    for part in parts:
        h.update(len(part).to_bytes(8, "big"))
        h.update(part)
    return h.hexdigest()


@dataclass(frozen=True)
class SchnorrSignature:
    domain: str
    announcement_hex: str
    response: int

    def to_dict(self) -> dict:
        return asdict(self)


def schnorr_sign(signing_key: int, message: bytes, domain: str) -> SchnorrSignature:
    nonce = secrets.randbelow(SCALAR_ORDER - 1) + 1
    announcement = hspdz_vss.scalar_base_multiply(nonce)
    public_key = hspdz_vss.scalar_base_multiply(signing_key)
    challenge = _hash_scalar(
        domain.encode(),
        _point_hex(announcement).encode(),
        _point_hex(public_key).encode(),
        message,
    )
    response = (nonce + challenge * int(signing_key)) % SCALAR_ORDER
    return SchnorrSignature(domain, _point_hex(announcement), response)


def schnorr_verify(public_key: hspdz_vss.Commitment, message: bytes, signature: SchnorrSignature) -> bool:
    try:
        announcement = point_from_hex(signature.announcement_hex)
    except ValueError:
        return False
    challenge = _hash_scalar(
        signature.domain.encode(),
        signature.announcement_hex.encode(),
        _point_hex(public_key).encode(),
        message,
    )
    left = hspdz_vss.scalar_base_multiply(signature.response)
    right = hspdz_vss.point_add(announcement, hspdz_vss.scalar_multiply(public_key, challenge))
    return hspdz_vss.equal(left, right)


@dataclass(frozen=True)
class SignedTranscript:
    domain: str
    session_id: str
    level_id: int
    transition_id: str
    sender_id: int
    receiver_id: int
    sequence_number: int
    commitment_id: str
    payload_digest: str
    public_key_hex: str
    signature: SchnorrSignature

    def signed_payload(self) -> dict:
        return {
            "domain": self.domain,
            "session_id": self.session_id,
            "level_id": self.level_id,
            "transition_id": self.transition_id,
            "sender_id": self.sender_id,
            "receiver_id": self.receiver_id,
            "sequence_number": self.sequence_number,
            "commitment_id": self.commitment_id,
            "payload_digest": self.payload_digest,
            "public_key_hex": self.public_key_hex,
        }

    def message_bytes(self) -> bytes:
        return _canonical_bytes(self.signed_payload())

    def evidence_digest(self) -> str:
        return _hash_hex(_canonical_bytes(self.to_dict()))

    def to_dict(self) -> dict:
        return {
            **self.signed_payload(),
            "signature": self.signature.to_dict(),
        }


def point_from_hex(encoded: str) -> hspdz_vss.Commitment:
    raw = bytes.fromhex(encoded)
    if len(raw) != 64:
        raise ValueError("invalid point encoding length")
    from py_ecc.fields import optimized_bn128_FQ as FQ
    from py_ecc.optimized_bn128 import is_on_curve
    from py_ecc.optimized_bn128.optimized_curve import b

    x = FQ(int.from_bytes(raw[:32], "big"))
    y = FQ(int.from_bytes(raw[32:], "big"))
    point = (x, y, FQ.one())
    if not is_on_curve(point, b):
        raise ValueError("point is not on BN254 G1")
    return point


def create_signed_transcript(
    *,
    signing_key: int,
    session_id: str,
    level_id: int,
    transition_id: str,
    sender_id: int,
    receiver_id: int,
    sequence_number: int,
    commitment_id: str,
    payload_digest: str,
    domain: str = "hspdz-transition-message-v1",
) -> SignedTranscript:
    public_key = hspdz_vss.scalar_base_multiply(signing_key)
    unsigned = {
        "domain": domain,
        "session_id": session_id,
        "level_id": level_id,
        "transition_id": transition_id,
        "sender_id": sender_id,
        "receiver_id": receiver_id,
        "sequence_number": sequence_number,
        "commitment_id": commitment_id,
        "payload_digest": payload_digest,
        "public_key_hex": _point_hex(public_key),
    }
    signature = schnorr_sign(signing_key, _canonical_bytes(unsigned), domain)
    return SignedTranscript(signature=signature, **unsigned)


def verify_signed_transcript(
    transcript: SignedTranscript,
    *,
    expected_public_key: hspdz_vss.Commitment | None = None,
) -> bool:
    try:
        public_key = point_from_hex(transcript.public_key_hex)
    except ValueError:
        return False
    if expected_public_key is not None and not hspdz_vss.equal(public_key, expected_public_key):
        return False
    return schnorr_verify(public_key, transcript.message_bytes(), transcript.signature)


@dataclass(frozen=True)
class TransitionSigmaProof:
    domain: str
    context_digest: str
    source_announcement_hex: str
    sub_announcement_hex: list[str]
    response_values: list[int]
    response_blinds: list[int]
    challenge: int

    def to_dict(self) -> dict:
        return asdict(self)

    def encoded_size(self) -> int:
        return len(_canonical_bytes(self.to_dict()))


def _transition_context_digest(
    context: dict,
    source_commitment: hspdz_vss.Commitment,
    sub_commitments: Iterable[hspdz_vss.Commitment],
    signed_transcripts: Iterable[SignedTranscript],
) -> str:
    payload = {
        "context": context,
        "source_commitment": _point_hex(source_commitment),
        "sub_commitments": [_point_hex(c) for c in sub_commitments],
        "signed_transcripts": [t.evidence_digest() for t in signed_transcripts],
    }
    return _hash_hex(_canonical_bytes(payload))


def _transition_challenge(
    context_digest: str,
    source_commitment: hspdz_vss.Commitment,
    sub_commitments: list[hspdz_vss.Commitment],
    source_announcement: hspdz_vss.Commitment,
    sub_announcements: list[hspdz_vss.Commitment],
) -> int:
    payload = {
        "domain": "hspdz-transition-sigma-v1",
        "context_digest": context_digest,
        "source_commitment": _point_hex(source_commitment),
        "sub_commitments": [_point_hex(c) for c in sub_commitments],
        "source_announcement": _point_hex(source_announcement),
        "sub_announcements": [_point_hex(a) for a in sub_announcements],
    }
    return _hash_scalar(_canonical_bytes(payload))


def prove_transition_consistency(
    *,
    context: dict,
    source_commitment: hspdz_vss.Commitment,
    sub_commitments: list[hspdz_vss.Commitment],
    source_value: int,
    source_blind: int,
    subshares: list[int],
    sub_blinds: list[int],
    signed_transcripts: list[SignedTranscript],
) -> TransitionSigmaProof:
    if len(sub_commitments) != len(subshares) or len(subshares) != len(sub_blinds):
        raise ValueError("transition witness length mismatch")
    if len(signed_transcripts) != len(subshares):
        raise ValueError("one signed transcript is required per receiver")

    if not hspdz_vss.equal(hspdz_vss.commit(source_value, source_blind), source_commitment):
        raise ValueError("source opening does not match source commitment")
    for commitment, subshare, blind in zip(sub_commitments, subshares, sub_blinds):
        if not hspdz_vss.equal(hspdz_vss.commit(subshare, blind), commitment):
            raise ValueError("subshare opening does not match sub-commitment")
    if not hspdz_vss.equal(hspdz_vss.combine(sub_commitments), source_commitment):
        raise ValueError("sub-commitments do not conserve the source commitment")

    masks_values = [secrets.randbelow(SCALAR_ORDER) for _ in subshares]
    masks_blinds = [secrets.randbelow(SCALAR_ORDER) for _ in subshares]
    source_mask_value = sum(masks_values) % SCALAR_ORDER
    source_mask_blind = sum(masks_blinds) % SCALAR_ORDER

    source_announcement = hspdz_vss.commit(source_mask_value, source_mask_blind)
    sub_announcements = [
        hspdz_vss.commit(mask_value, mask_blind)
        for mask_value, mask_blind in zip(masks_values, masks_blinds)
    ]
    context_digest = _transition_context_digest(
        context, source_commitment, sub_commitments, signed_transcripts
    )
    challenge = _transition_challenge(
        context_digest,
        source_commitment,
        sub_commitments,
        source_announcement,
        sub_announcements,
    )

    response_values = [
        (mask + challenge * _scalar(value)) % SCALAR_ORDER
        for mask, value in zip(masks_values, subshares)
    ]
    response_blinds = [
        (mask + challenge * _scalar(blind)) % SCALAR_ORDER
        for mask, blind in zip(masks_blinds, sub_blinds)
    ]

    return TransitionSigmaProof(
        domain="hspdz-transition-sigma-v1",
        context_digest=context_digest,
        source_announcement_hex=_point_hex(source_announcement),
        sub_announcement_hex=[_point_hex(a) for a in sub_announcements],
        response_values=response_values,
        response_blinds=response_blinds,
        challenge=challenge,
    )


def verify_transition_consistency_proof(
    *,
    context: dict,
    source_commitment: hspdz_vss.Commitment,
    sub_commitments: list[hspdz_vss.Commitment],
    signed_transcripts: list[SignedTranscript],
    proof: TransitionSigmaProof,
) -> bool:
    if proof.domain != "hspdz-transition-sigma-v1":
        return False
    n = len(sub_commitments)
    if (
        len(proof.sub_announcement_hex) != n
        or len(proof.response_values) != n
        or len(proof.response_blinds) != n
        or len(signed_transcripts) != n
    ):
        return False
    context_digest = _transition_context_digest(
        context, source_commitment, sub_commitments, signed_transcripts
    )
    if context_digest != proof.context_digest:
        return False

    try:
        source_announcement = point_from_hex(proof.source_announcement_hex)
        sub_announcements = [point_from_hex(encoded) for encoded in proof.sub_announcement_hex]
    except ValueError:
        return False

    expected_challenge = _transition_challenge(
        context_digest,
        source_commitment,
        sub_commitments,
        source_announcement,
        sub_announcements,
    )
    if expected_challenge != proof.challenge:
        return False

    for commitment, announcement, value_response, blind_response in zip(
        sub_commitments,
        sub_announcements,
        proof.response_values,
        proof.response_blinds,
    ):
        left = hspdz_vss.commit(value_response, blind_response)
        right = hspdz_vss.point_add(
            announcement,
            hspdz_vss.scalar_multiply(commitment, proof.challenge),
        )
        if not hspdz_vss.equal(left, right):
            return False

    source_left = hspdz_vss.commit(
        sum(proof.response_values) % SCALAR_ORDER,
        sum(proof.response_blinds) % SCALAR_ORDER,
    )
    source_right = hspdz_vss.point_add(
        source_announcement,
        hspdz_vss.scalar_multiply(source_commitment, proof.challenge),
    )
    return hspdz_vss.equal(source_left, source_right)


def digest_transition_payload(*, receiver_id: int, commitment: hspdz_vss.Commitment) -> str:
    payload = {
        "receiver_id": receiver_id,
        "commitment": _point_hex(commitment),
    }
    return _hash_hex(_canonical_bytes(payload))


def classify_dispute_event(event: str) -> str:
    matrix = {
        "invalid_commitment_encoding": "SOURCE_FAULT",
        "subshare_inconsistent_with_valid_signed_transcript": "SOURCE_FAULT",
        "invalid_sender_signature": "SOURCE_FAULT",
        "receiver_receipt_contradicts_sender": "ATTRIBUTED_BY_SIGNATURES",
        "invalid_conservation": "SOURCE_FAULT",
        "missing_message_without_deposit_proof": "UNATTRIBUTABLE_ABORT_RETRY",
        "timeout_or_partition": "UNATTRIBUTABLE_ABORT_RETRY_RECONFIGURE",
        "invalid_sigma_proof": "PROVER_FAULT",
        "proof_not_supplied_before_deadline": "AVAILABILITY_FAILURE",
    }
    if event not in matrix:
        raise ValueError(f"unknown dispute event {event!r}")
    return matrix[event]
