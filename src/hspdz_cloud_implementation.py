
"""
H-SPDZ-Cloud: A Formal Prototype for Hierarchical Authenticated MPC
in Edge--Fog--Cloud Architectures
Complete Implementation with Experimental Benchmarks

This implementation is the proof-of-concept prototype accompanying the study:
"H-SPDZ-Cloud: A Formal Prototype for Hierarchical Authenticated MPC
in Edge--Fog--Cloud Architectures"

Author: Research Team
License: Academic Use

=============================================================================
SIMULATION MODEL — VALIDATION SCOPE FOR THE DISTRIBUTED PROTOCOL
=============================================================================

This module provides a single-process simulation of the H-SPDZ-Cloud protocol.
Two deliberate single-process shortcuts support reproducibility while preserving
functional correctness of the measured scenarios and simplifying the distributed
security model described in the associated publication:

(S1) MAC KEY RECONSTRUCTION — Single-process audit shortcut.
     The protocol description keeps the global MAC key α_ℓ in virtual
     shared form. In this simulation, α_ℓ is reconstructed only by
     simulator audit/test helpers; normal
     share authentication keeps per-party MAC-key shares for subsequent
     operations. In a real distributed deployment, each party would
     hold only its share [α_ℓ]^(i) and all MAC operations would use
     Algorithm 1 (authenticated MAC generation via auxiliary triple)
     to avoid ever assembling α_ℓ in a single process.

(S2) SECRET RECONSTRUCTION IN RECOVERY — Centralized simulation shortcut.
     The protocol description uses checkpoint recovery in which each honest
     party keeps its individual checkpoint share private. In this simulation,
     recover_from_checkpoint
     receives a plain integer checkpoint_val that the caller obtains via
     proto.reconstruct().  In a real deployment, each honest party would
     sub-share its own private share [z*]^(i) among H_ℓ without anyone
     assembling z*; the faulty party's revealed share would be absorbed
     as a public addend into a designated honest party's sub-share.

These shortcuts are consistent with the single-host virtualized
proof-of-concept framing of the reproducible prototype evaluation
and are included in the validation scope of the associated publication.
A fully distributed implementation addressing these orchestration shortcuts is deferred to
future work (§IX.B, direction 1).
=============================================================================
"""

import os
import numpy as np
import matplotlib.pyplot as plt
import time
import hashlib
import secrets
from typing import List, Tuple, Dict, Optional
from dataclasses import dataclass
from collections import defaultdict
import json
import hspdz_dispute
import hspdz_vss

# ==================== CRYPTOGRAPHIC PARAMETERS ====================
SECURITY_BITS = 128
P = 2**127 - 1  # 128-bit-size Mersenne prime for finite field F_p

def field_bytes(p: int = P) -> int:
    """Number of bytes required to encode one field element."""
    return (p.bit_length() + 7) // 8

FIELD_BYTES = field_bytes(P)

def mod(x, p: int = P):
    """Modular reduction in F_p"""
    return x % p

def rand_field(p: int = P):
    """Uniform random element in F_p"""
    return secrets.randbelow(p)

def rand_commit_blind():
    """Uniform random blinding exponent for transition commitments."""
    return hspdz_vss.random_blind()

def pedersen_commit(value: int, blind: int) -> int:
    """Pedersen commitment over a prime-order elliptic-curve group."""
    return hspdz_vss.commit(value, blind)

# ==================== DATA STRUCTURES ====================

@dataclass
class AuthenticatedShare:
    """
    Authenticated additive sharing at level ℓ.
    ⟨x⟩_ℓ = ([x]_ℓ, [t_ℓ(x)]_ℓ) where t_ℓ(x) = α_ℓ · x
    """
    shares: np.ndarray      # [x]_ℓ^(i) for each party i
    mac_shares: np.ndarray  # [t_ℓ(x)]_ℓ^(i) for each party i
    level: int              # Hierarchical level ℓ

@dataclass
class AuthenticatedMask:
    """Fresh one-time authenticated mask used by the masked batch MAC check."""
    value: AuthenticatedShare
    mask_id: str
    used: bool = False

@dataclass  
class BeaverTriple:
    """
    Authenticated Beaver triple ⟨a,b,c⟩_ℓ with c = a·b
    Pre-computed during offline stage via MASCOT-like OT extension
    """
    a: AuthenticatedShare
    b: AuthenticatedShare
    c: AuthenticatedShare

class LevelParty:
    """
    Represents a single party P_i^ℓ at hierarchical level ℓ.
    Maintains local state: MAC key share, storage, commitments.
    """
    def __init__(self, level_id: int, party_id: int, num_parties: int, field_prime: int = P):
        self.level_id = level_id
        self.party_id = party_id
        self.num_parties = num_parties
        # Each party holds a share of the level MAC key α_ℓ
        self.alpha_share = rand_field(field_prime)
        self.storage = {}
        self.commitments = {}
        self.randomness = {}
        self.signing_key = rand_commit_blind()
        self.verification_key = hspdz_vss.scalar_base_multiply(self.signing_key)

# ==================== MAIN PROTOCOL ====================

class HSPDZCloud:
    """
    H-SPDZ-Cloud Protocol Implementation.

    Security assumptions:
    - Static, active adversary
    - Honest majority per level: t_ℓ < n_ℓ/2
    - Authenticated private channels
    - Random Oracle Model for hash commitments
    """

    def __init__(self, level_sizes: List[int], field_prime: int = P):
        self.p = field_prime
        self.field_bytes = field_bytes(self.p)
        self.level_sizes = level_sizes
        self.num_levels = len(level_sizes)
        self.levels = []
        self.triple_pools = defaultdict(list)
        self._batch_counter = 0
        self._mask_counter = 0
        self._transition_counter = 0
        self._consumed_masks = set()

        # Performance metrics collector
        self.metrics = {
            'communication_bytes': 0,
            'rounds': 0,
            'latency_ms': 0,
            'multiplications': 0,
            'transitions': 0,
            'fault_detections': 0,
            'transition_proof_failures': 0,
            'transition_sigma_proofs': 0,
            'transition_sigma_gen_ms': 0,
            'transition_sigma_verify_ms': 0,
            'transition_signed_transcripts': 0,
            'offline_time_ms': 0
        }

        # Initialize hierarchical parties
        for level_idx, n in enumerate(level_sizes):
            parties = [LevelParty(level_idx, i, n, self.p) for i in range(n)]
            self.levels.append(parties)

        # MAC keys are represented only through per-party shares. The helper
        # mac_key_for_audit is used only where the single-process simulator must
        # emulate an opening or model a corrupt quorum.

    def mac_key_for_audit(self, level: int) -> int:
        """Reconstruct alpha_l inside the simulator for audit/test checks only."""
        return sum(p.alpha_share for p in self.levels[level]) % self.p

    def _share_plain(self, secret: int, n: int) -> np.ndarray:
        shares = [rand_field(self.p) for _ in range(n - 1)]
        shares.append((secret - sum(shares)) % self.p)
        return np.array(shares, dtype=object)

    def _authenticate_value_shares(self, shares: np.ndarray, level: int) -> np.ndarray:
        """
        Compute shares of alpha_l * v from shares of v and alpha_l using the
        masked-opening multiplication pattern of Algorithm 1.
        """
        n = self.level_sizes[level]
        r = rand_field(self.p)
        s = rand_field(self.p)
        rs = (r * s) % self.p
        r_shares = self._share_plain(r, n)
        s_shares = self._share_plain(s, n)
        rs_shares = self._share_plain(rs, n)
        alpha_shares = np.array([p.alpha_share for p in self.levels[level]], dtype=object)

        epsilon = int(sum((shares - r_shares) % self.p)) % self.p
        delta = int(sum((alpha_shares - s_shares) % self.p)) % self.p

        mac_shares = np.zeros(n, dtype=object)
        for i in range(n):
            mac_shares[i] = (
                rs_shares[i]
                + epsilon * s_shares[i]
                + delta * r_shares[i]
                + (epsilon * delta if i == 0 else 0)
            ) % self.p
        return mac_shares

    def share_secret(self, secret: int, level: int) -> AuthenticatedShare:
        """
        Create authenticated additive sharing of secret at level ℓ.
        Perfect information-theoretic confidentiality for t_ℓ < n_ℓ.
        """
        n = self.level_sizes[level]
        # Additive shares: random n-1 shares, last one balances
        shares = self._share_plain(secret, n)

        # MAC authentication with level key α_ℓ
        mac_shares = self._authenticate_value_shares(shares, level)

        return AuthenticatedShare(shares, mac_shares, level)

    def reconstruct(self, auth_share: AuthenticatedShare) -> int:
        """Reconstruct secret (for verification/debug only)."""
        return int(sum(auth_share.shares)) % self.p

    def verify_mac(self, auth_share: AuthenticatedShare) -> bool:
        """
        Verify MAC integrity: Σ[t_ℓ(x)] == α_ℓ · Σ[x]
        Audit helper for the single-process simulator.
        """
        x = int(sum(auth_share.shares)) % self.p
        t = int(sum(auth_share.mac_shares)) % self.p
        alpha = self.mac_key_for_audit(auth_share.level)
        return t == (alpha * x) % self.p

    def generate_triple(self, level: int) -> BeaverTriple:
        """
        Offline generation of authenticated Beaver triple.
        Simulates MASCOT OT-extension approach.
        Complexity: O(n_ℓ² log p + κ n_ℓ) bits per triple.
        """
        a = rand_field(self.p)
        b = rand_field(self.p)
        c = (a * b) % self.p

        a_auth = self.share_secret(a, level)
        b_auth = self.share_secret(b, level)
        c_auth = self.share_secret(c, level)

        # Account for offline communication
        self.metrics['communication_bytes'] += self.level_sizes[level] * self.field_bytes * 3

        return BeaverTriple(a_auth, b_auth, c_auth)

    # ==================== LINEAR OPERATIONS (FREE) ====================

    def add(self, x: AuthenticatedShare, y: AuthenticatedShare) -> AuthenticatedShare:
        """Local addition: [x+y] = [x] + [y], [t(x+y)] = [t(x)] + [t(y)]"""
        assert x.level == y.level
        return AuthenticatedShare(
            (x.shares + y.shares) % self.p,
            (x.mac_shares + y.mac_shares) % self.p,
            x.level
        )

    def multiply_by_constant(self, x: AuthenticatedShare, k: int) -> AuthenticatedShare:
        """Local scalar multiplication."""
        k = k % self.p
        return AuthenticatedShare(
            (x.shares * k) % self.p,
            (x.mac_shares * k) % self.p,
            x.level
        )

    # ==================== SECURE MULTIPLICATION ====================

    def multiply(self, x: AuthenticatedShare, y: AuthenticatedShare, 
                 triple: BeaverTriple) -> AuthenticatedShare:
        """
        Secure multiplication consuming one Beaver triple.
        Algorithm 2 in the protocol description.

        Communication: 2 openings = O(n_ℓ log p) bits, 1 round.
        """
        assert x.level == y.level == triple.a.level
        level = x.level
        n = self.level_sizes[level]

        # Step 1 & 2: Open masked values
        epsilon_shares = (x.shares - triple.a.shares) % self.p
        epsilon = int(sum(epsilon_shares)) % self.p

        delta_shares = (y.shares - triple.b.shares) % self.p
        delta = int(sum(delta_shares)) % self.p

        # Communication cost
        self.metrics['communication_bytes'] += n * self.field_bytes * 2
        self.metrics['rounds'] += 1
        self.metrics['multiplications'] += 1

        # Step 3: Local recomputation
        z_shares = np.zeros(n, dtype=object)
        t_z_shares = np.zeros(n, dtype=object)

        for i in range(n):
            # z = c + ε·b + δ·a + ε·δ·I[i=1]
            term1 = (epsilon * triple.b.shares[i]) % self.p
            term2 = (delta * triple.a.shares[i]) % self.p
            term3 = (epsilon * delta) if i == 0 else 0
            z_shares[i] = (triple.c.shares[i] + term1 + term2 + term3) % self.p

            # MAC: t(z) = t(c) + ε·t(b) + δ·t(a) + ε·δ·α
            mac1 = (epsilon * triple.b.mac_shares[i]) % self.p
            mac2 = (delta * triple.a.mac_shares[i]) % self.p
            mac3 = (epsilon * delta * self.levels[level][i].alpha_share) % self.p
            t_z_shares[i] = (triple.c.mac_shares[i] + mac1 + mac2 + mac3) % self.p

        return AuthenticatedShare(z_shares, t_z_shares, level)

    # ==================== BATCH VERIFICATION ====================

    def bind_batch_state(
        self,
        values: List[AuthenticatedShare],
        level: int,
        session_id: Optional[str] = None,
        batch_id: Optional[int] = None,
    ) -> Dict:
        """
        Bind the batch transcript before deriving public challenges.

        The digest represents public commitments to the already-fixed simulator
        state. A deployment would use canonical commitments or signed digests
        rather than raw local arrays.
        """
        if session_id is None:
            session_id = secrets.token_hex(16)
        if batch_id is None:
            self._batch_counter += 1
            batch_id = self._batch_counter
        return {
            "domain": "hspdz-batch-state-v1",
            "session_id": session_id,
            "level": level,
            "batch_id": batch_id,
            "batch_size": len(values),
            "state_digest": self._batch_state_digest(values, level, session_id, batch_id),
        }

    def _batch_state_digest(
        self,
        values: List[AuthenticatedShare],
        level: int,
        session_id: str,
        batch_id: int,
    ) -> str:
        h = hashlib.sha256()
        h.update(b"hspdz-batch-state-v1")
        h.update(str(session_id).encode())
        h.update(str(level).encode())
        h.update(str(batch_id).encode())
        h.update(str(len(values)).encode())
        for index, val in enumerate(values):
            if val.level != level:
                raise ValueError("all batch values must belong to the verified level")
            h.update(str(index).encode())
            for share, mac_share in zip(val.shares, val.mac_shares):
                h.update(int(share).to_bytes(self.field_bytes, "big", signed=False))
                h.update(int(mac_share).to_bytes(self.field_bytes, "big", signed=False))
        return h.hexdigest()

    def derive_batch_challenges(self, binding: Dict) -> List[int]:
        """Derive independent Fiat-Shamir coefficients after state binding."""
        if binding.get("domain") != "hspdz-batch-state-v1":
            raise ValueError("invalid batch-binding domain")
        challenges = []
        for j in range(int(binding["batch_size"])):
            h = hashlib.sha256()
            h.update(b"hspdz-batch-rho-v1")
            h.update(str(binding["session_id"]).encode())
            h.update(str(binding["level"]).encode())
            h.update(str(binding["batch_id"]).encode())
            h.update(str(j).encode())
            h.update(str(binding["state_digest"]).encode())
            challenges.append(int.from_bytes(h.digest(), "big") % self.p)
        return challenges

    def generate_authenticated_mask(self, level: int) -> AuthenticatedMask:
        """Generate a fresh authenticated one-time mask ⟨r⟩_ℓ."""
        self._mask_counter += 1
        mask_value = rand_field(self.p)
        mask = self.share_secret(mask_value, level)
        return AuthenticatedMask(mask, f"L{level}-mask-{self._mask_counter}")

    def _consume_mask(self, mask: AuthenticatedMask, level: int) -> AuthenticatedShare:
        if mask.value.level != level:
            raise ValueError("mask level does not match batch level")
        if mask.used or mask.mask_id in self._consumed_masks:
            raise ValueError("authenticated mask reuse detected")
        mask.used = True
        self._consumed_masks.add(mask.mask_id)
        return mask.value

    def _commit_then_open_check_shares(
        self,
        e_shares: np.ndarray,
        binding: Dict,
        tamper_for_test: bool = False,
    ) -> bool:
        nonces = [secrets.token_hex(16) for _ in e_shares]
        commitments = []
        for i, share in enumerate(e_shares):
            payload = f"{binding['session_id']}:{binding['batch_id']}:{i}:{int(share)}:{nonces[i]}"
            commitments.append(hashlib.sha256(payload.encode()).hexdigest())

        opened = np.array(e_shares, dtype=object)
        if tamper_for_test and len(opened) > 0:
            opened[0] = (opened[0] + 1) % self.p

        for i, share in enumerate(opened):
            payload = f"{binding['session_id']}:{binding['batch_id']}:{i}:{int(share)}:{nonces[i]}"
            if hashlib.sha256(payload.encode()).hexdigest() != commitments[i]:
                return False
        return int(sum(opened)) % self.p == 0

    def batch_verify(
        self,
        values: List[AuthenticatedShare],
        level: int,
        binding: Optional[Dict] = None,
        coefficients: Optional[List[int]] = None,
        mask: Optional[AuthenticatedMask] = None,
        _tamper_check_share_for_test: bool = False,
    ) -> bool:
        """
        Masked batch MAC verification with independent public coefficients.

        The protocol binds the state, derives public coefficients rho_j,
        combines authenticated values locally, consumes a fresh authenticated
        mask ⟨r⟩_ℓ, opens only u=w-r, and commit-then-opens the check shares
        e_i = gamma_w_i - gamma_r_i - u*alpha_i.
        """
        if not values:
            return True

        n = self.level_sizes[level]
        if binding is None:
            if coefficients is not None:
                raise ValueError("externally supplied coefficients require a prior batch binding")
            binding = self.bind_batch_state(values, level)
        else:
            expected = self._batch_state_digest(
                values,
                level,
                str(binding["session_id"]),
                int(binding["batch_id"]),
            )
            if expected != binding.get("state_digest"):
                raise ValueError("batch state changed after challenge binding")

        if coefficients is None:
            coefficients = self.derive_batch_challenges(binding)
        if len(coefficients) != len(values):
            raise ValueError("challenge count does not match batch size")

        mask_value = self._consume_mask(mask or self.generate_authenticated_mask(level), level)

        w_shares = np.zeros(n, dtype=object)
        gamma_w_shares = np.zeros(n, dtype=object)

        for j, val in enumerate(values):
            coeff = int(coefficients[j]) % self.p
            w_shares = (w_shares + (val.shares * coeff) % self.p) % self.p
            gamma_w_shares = (gamma_w_shares + (val.mac_shares * coeff) % self.p) % self.p

        u_shares = (w_shares - mask_value.shares) % self.p
        u = int(sum(u_shares)) % self.p
        alpha_shares = np.array([p.alpha_share for p in self.levels[level]], dtype=object)
        e_shares = (gamma_w_shares - mask_value.mac_shares - (u * alpha_shares) % self.p) % self.p

        self.metrics['communication_bytes'] += n * (2 * self.field_bytes + 48)
        self.metrics['rounds'] += 1
        self.metrics['batch_masks_consumed'] = self.metrics.get('batch_masks_consumed', 0) + 1

        return self._commit_then_open_check_shares(e_shares, binding, _tamper_check_share_for_test)

    # ==================== INTER-LEVEL TRANSITION ====================

    def commit_transition(self, val: AuthenticatedShare, next_level: int) -> Dict:
        """
        Pre-transition commitment stage.
        Each P_i^ℓ commits to H([z]_ℓ^(i) || r_i).
        """
        level = val.level
        n_curr = self.level_sizes[level]
        self._transition_counter += 1
        session_id = secrets.token_hex(16)
        transition_id = f"L{level}-to-L{next_level}-{self._transition_counter}"

        commitments = {}
        randomness = {}
        value_commitments = {}
        commitment_blinds = {}

        for i in range(n_curr):
            r_i = rand_field(self.p)
            randomness[i] = r_i
            data = f"{val.shares[i]}:{r_i}".encode()
            commitments[i] = hashlib.sha256(data).hexdigest()
            rho_i = rand_commit_blind()
            commitment_blinds[i] = rho_i
            value_commitments[i] = pedersen_commit(int(val.shares[i]), rho_i)

        self.metrics['communication_bytes'] += n_curr * (32 + 64)  # SHA-256 + EC commitment

        return {
            'commitments': commitments, 
            'randomness': randomness, 
            'value_commitments': value_commitments,
            'commitment_blinds': commitment_blinds,
            'session_id': session_id,
            'level_id': level,
            'next_level': next_level,
            'transition_id': transition_id,
            'n_next': self.level_sizes[next_level]
        }

    def transition_level(self, val: AuthenticatedShare, next_level: int, 
                         commit_data: Dict, 
                         corrupt_parties: List[int] = None) -> Tuple[Optional[AuthenticatedShare], Optional[List[int]]]:
        """
        Secure transition ℓ → ℓ+1 with commitment verification.
        Algorithm 3 in the protocol description.

        Returns: (new_auth_share, None) on success,
                 (None, malicious_set) on failure.
        """
        if corrupt_parties is None:
            corrupt_parties = []

        level = val.level
        n_curr = self.level_sizes[level]
        n_next = self.level_sizes[next_level]

        # Step 1: Additive resharing with fresh randomness
        new_shares = np.zeros(n_next, dtype=object)
        subshares = {}
        sub_blinds = {}
        sub_commitments = {}
        signed_transcripts = {}
        transition_proofs = {}
        proof_gen_ms = 0.0

        for i in range(n_curr):
            sub_shares = [rand_field(self.p) for _ in range(n_next - 1)]
            original_share = int(val.shares[i])

            if i in corrupt_parties:
                original_share = (original_share + 1) % self.p  # Simulate corruption

            last = original_share - sum(sub_shares)
            sub_shares.append(last)
            subshares[i] = sub_shares

            rho_i = commit_data['commitment_blinds'][i]
            blinds = [rand_commit_blind() for _ in range(n_next - 1)]
            blinds.append((rho_i - sum(blinds)) % hspdz_vss.curve_order)
            sub_blinds[i] = blinds
            sub_commitments[i] = [
                pedersen_commit(sub_shares[j], blinds[j]) for j in range(n_next)
            ]
            source_party = self.levels[level][i]
            context = {
                "session_id": commit_data.get("session_id", ""),
                "level_id": level,
                "next_level": next_level,
                "transition_id": commit_data.get("transition_id", ""),
                "source_id": i,
                "n_next": n_next,
            }
            transcripts = []
            for j in range(n_next):
                payload_digest = hspdz_dispute.digest_transition_payload(
                    receiver_id=j,
                    commitment=sub_commitments[i][j],
                )
                transcripts.append(
                    hspdz_dispute.create_signed_transcript(
                        signing_key=source_party.signing_key,
                        session_id=str(context["session_id"]),
                        level_id=level,
                        transition_id=str(context["transition_id"]),
                        sender_id=i,
                        receiver_id=j,
                        sequence_number=j,
                        commitment_id=f"{context['transition_id']}:src{i}:recv{j}",
                        payload_digest=payload_digest,
                    )
                )
            signed_transcripts[i] = transcripts
            self.metrics['transition_signed_transcripts'] += len(transcripts)

            proof_start = time.perf_counter()
            try:
                transition_proofs[i] = hspdz_dispute.prove_transition_consistency(
                    context=context,
                    source_commitment=commit_data['value_commitments'][i],
                    sub_commitments=sub_commitments[i],
                    source_value=int(val.shares[i]),
                    source_blind=int(commit_data['commitment_blinds'][i]),
                    subshares=[int(x) for x in sub_shares],
                    sub_blinds=[int(x) for x in blinds],
                    signed_transcripts=transcripts,
                )
            except ValueError:
                transition_proofs[i] = None
            proof_gen_ms += (time.perf_counter() - proof_start) * 1000

            for j in range(n_next):
                new_shares[j] = (new_shares[j] + sub_shares[j]) % self.p

        self.metrics['transition_sigma_gen_ms'] += proof_gen_ms
        self.metrics['communication_bytes'] += n_curr * n_next * (self.field_bytes + 32 + 64)
        self.metrics['transitions'] += 1

        # Step 2: normal-path verifiable resharing.
        malicious = []
        proof_verify_ms = 0.0
        for i in range(n_curr):
            receiver_openings_valid = all(
                pedersen_commit(subshares[i][j], sub_blinds[i][j]) == sub_commitments[i][j]
                for j in range(n_next)
            )
            aggregate_commitment = hspdz_vss.combine(sub_commitments[i])
            # The simulator checks the algebraic statement that the proof would
            # establish in a deployment: the private sub-shares sum to the
            # committed source share in F_p. The public commitments above bind
            # the checked openings in this proof-of-concept implementation.
            aggregate_valid = (
                (sum(subshares[i]) - int(val.shares[i])) % self.p == 0
                and hspdz_vss.equal(aggregate_commitment, commit_data['value_commitments'][i])
            )
            expected_key = self.levels[level][i].verification_key
            signatures_valid = all(
                hspdz_dispute.verify_signed_transcript(t, expected_public_key=expected_key)
                for t in signed_transcripts[i]
            )
            context = {
                "session_id": commit_data.get("session_id", ""),
                "level_id": level,
                "next_level": next_level,
                "transition_id": commit_data.get("transition_id", ""),
                "source_id": i,
                "n_next": n_next,
            }
            proof_start = time.perf_counter()
            proof_valid = transition_proofs[i] is not None and hspdz_dispute.verify_transition_consistency_proof(
                context=context,
                source_commitment=commit_data['value_commitments'][i],
                sub_commitments=sub_commitments[i],
                signed_transcripts=signed_transcripts[i],
                proof=transition_proofs[i],
            )
            proof_verify_ms += (time.perf_counter() - proof_start) * 1000
            if proof_valid:
                self.metrics['transition_sigma_proofs'] += 1

            if not receiver_openings_valid or not aggregate_valid or not signatures_valid or not proof_valid:
                malicious.append(i)

        self.metrics['transition_sigma_verify_ms'] += proof_verify_ms

        if malicious:
            self.metrics['fault_detections'] += 1
            self.metrics['transition_proof_failures'] += len(malicious)
            return None, malicious

        # Step 3: Re-authentication with α_{ℓ+1} (independent key)
        mac_shares = self._authenticate_value_shares(new_shares, next_level)

        new_auth = AuthenticatedShare(new_shares, mac_shares, next_level)

        # Sanity check: secret preservation
        assert self.reconstruct(new_auth) == self.reconstruct(val)

        return new_auth, None

    # ==================== FAULT RECOVERY ====================

    def recover_from_checkpoint(self, checkpoint_val: int, honest_parties: List[int], level: int) -> AuthenticatedShare:
        """
        Recovery without individual secret reconstruction.
        Honest parties collectively generate fresh sharing.
        """
        n_honest = len(honest_parties)
        new_shares = [rand_field(self.p) for _ in range(n_honest - 1)]
        last = (checkpoint_val - sum(new_shares)) % self.p
        new_shares.append(last)

        # Distribute to honest parties only
        full_shares = np.zeros(self.level_sizes[level], dtype=object)
        for idx, party_idx in enumerate(honest_parties):
            full_shares[party_idx] = new_shares[idx]

        # Fresh MAC key for the purified configuration, generated as shares
        # among the remaining honest parties.
        fresh_alpha_shares = self._share_plain(rand_field(self.p), n_honest)
        for idx, party_idx in enumerate(honest_parties):
            self.levels[level][party_idx].alpha_share = fresh_alpha_shares[idx]
        for party_idx in set(range(self.level_sizes[level])) - set(honest_parties):
            self.levels[level][party_idx].alpha_share = 0

        full_mac_shares = self._authenticate_value_shares(full_shares, level)

        return AuthenticatedShare(full_shares, full_mac_shares, level)


# ==================== EXPERIMENTAL FRAMEWORK ====================

class HSPDZExperiments:
    """Comprehensive test scenarios and performance benchmarks."""

    def __init__(self, protocol: HSPDZCloud):
        self.protocol = protocol

    def reset_metrics(self):
        self.protocol.metrics = {
            'communication_bytes': 0, 'rounds': 0, 'latency_ms': 0,
            'multiplications': 0, 'transitions': 0, 'fault_detections': 0,
            'transition_proof_failures': 0,
            'transition_sigma_proofs': 0,
            'transition_sigma_gen_ms': 0,
            'transition_sigma_verify_ms': 0,
            'transition_signed_transcripts': 0,
            'offline_time_ms': 0
        }

    def measure_latency(self, func, *args, **kwargs):
        start = time.perf_counter()
        result = func(*args, **kwargs)
        end = time.perf_counter()
        return result, (end - start) * 1000

    def scenario_1_nominal(self, n1=3, n2=2, n3=2):
        """Scenario 1: Nominal execution with realistic circuit."""
        self.reset_metrics()
        proto = HSPDZCloud([n1, n2, n3])

        # Circuit: z = (x1*w1 + x2*w2) * x3
        x1 = proto.share_secret(10, 0)
        x2 = proto.share_secret(5, 0)
        x3 = proto.share_secret(2, 0)
        w1 = proto.share_secret(3, 0)
        w2 = proto.share_secret(4, 0)

        triples = [proto.generate_triple(0) for _ in range(3)]

        t1, lat1 = self.measure_latency(proto.multiply, x1, w1, triples[0])
        t2, lat2 = self.measure_latency(proto.multiply, x2, w2, triples[1])
        s1 = proto.add(t1, t2)
        result_edge, lat3 = self.measure_latency(proto.multiply, s1, x3, triples[2])

        ok = proto.batch_verify([result_edge], 0)

        commit = proto.commit_transition(result_edge, 1)
        fog_result, _ = proto.transition_level(result_edge, 1, commit)
        commit2 = proto.commit_transition(fog_result, 2)
        cloud_result, _ = proto.transition_level(fog_result, 2, commit2)

        final = proto.reconstruct(cloud_result)
        expected = (10*3 + 5*4) * 2

        return {
            'scenario': 'nominal',
            'latency_ms': lat1+lat2+lat3,
            'comm_kb': proto.metrics['communication_bytes']/1024,
            'rounds': proto.metrics['rounds'],
            'correct': final == expected
        }

    def scenario_2_edge_fault(self, n1=3, n2=2, n3=2):
        """Scenario 2: Edge-level fault detection via MAC."""
        self.reset_metrics()
        proto = HSPDZCloud([n1, n2, n3])

        x1 = proto.share_secret(10, 0)
        x2 = proto.share_secret(5, 0)
        triple = proto.generate_triple(0)

        result, _ = self.measure_latency(proto.multiply, x1, x2, triple)
        result.shares[1] = (result.shares[1] + 1) % proto.p

        ok = proto.batch_verify([result], 0)
        return {'scenario': 'edge_fault', 'detected': not ok}

    def scenario_3_fog_transition_fault(self, n1=3, n2=2, n3=2):
        """Scenario 3: Transition fault detection."""
        self.reset_metrics()
        proto = HSPDZCloud([n1, n2, n3])

        x1 = proto.share_secret(10, 0)
        x2 = proto.share_secret(5, 0)
        triple = proto.generate_triple(0)

        result = proto.multiply(x1, x2, triple)
        proto.batch_verify([result], 0)

        commit = proto.commit_transition(result, 1)
        _, malicious = proto.transition_level(result, 1, commit, corrupt_parties=[1])

        return {'scenario': 'fog_transition_fault', 'detected': malicious is not None, 'malicious': malicious}

    def scenario_4_cloud_fault(self, n1=3, n2=2, n3=2):
        """Scenario 4: Cloud fault with checkpoint recovery."""
        proto = HSPDZCloud([n1, n2, n3])

        x1 = proto.share_secret(50, 0)
        commit = proto.commit_transition(x1, 1)
        fog_r, _ = proto.transition_level(x1, 1, commit)
        checkpoint = proto.reconstruct(fog_r)

        commit2 = proto.commit_transition(fog_r, 2)
        _, malicious = proto.transition_level(fog_r, 2, commit2, corrupt_parties=[0])

        if malicious:
            recovered = proto.recover_from_checkpoint(checkpoint, list(range(n2)), 1)
            return {'scenario': 'cloud_fault', 'detected': True, 'recovered': proto.reconstruct(recovered) == checkpoint}
        return {'scenario': 'cloud_fault', 'detected': False}

    def scenario_5_majority_corruption(self, n1=3, n2=2, n3=2):
        """
        Scenario 5: Majority corruption at the Edge level (theoretical limit).

        When t_1 >= n_1/2, colluding corrupt parties share a consistent
        false MAC key among themselves, so batch_verify passes on the
        corrupted value.  This confirms that t_ℓ < n_ℓ/2 is a strict
        security bound: the protocol provides no integrity guarantee once
        the honest majority is lost.

        Note: because this simulation centralises α_ℓ (see S1 in the
        module docstring), we model majority corruption by constructing
        a fresh protocol instance where the majority of parties hold
        consistent but wrong shares — effectively simulating a corrupt
        quorum that controls the MAC key.
        """
        self.reset_metrics()
        proto = HSPDZCloud([n1, n2, n3])

        secret = 42
        x = proto.share_secret(secret, 0)

        # Corrupt majority of Edge parties: overwrite shares AND mac_shares
        # consistently so the false MAC checks out (accomplices collude).
        num_corrupt = (n1 // 2) + 1   # strict majority
        corrupt_delta = 7             # arbitrary additive corruption
        for i in range(num_corrupt):
            x.shares[i] = (x.shares[i] + corrupt_delta) % proto.p
            # Accomplices recompute consistent MAC share for false value:
            # Each corrupt party adjusts its mac_share by α_ℓ * corrupt_delta
            # so that Σ mac_shares == α_ℓ * (secret + num_corrupt*corrupt_delta)
            x.mac_shares[i] = (x.mac_shares[i] +
                                proto.mac_key_for_audit(0) * corrupt_delta) % proto.p

        # batch_verify now PASSES because the corruption is MAC-consistent
        detected = not proto.batch_verify([x], 0)
        reconstructed = proto.reconstruct(x)

        return {
            'scenario': 'majority_corruption',
            'n1': n1,
            'num_corrupt': num_corrupt,
            'original_secret': secret,
            'reconstructed_value': reconstructed,
            'integrity_lost': reconstructed != secret,
            'batch_verify_detected': detected,
            'confirms_strict_majority_bound': (not detected) and (reconstructed != secret),
        }

    def scenario_7_cascade_faults(self, n1=3, n2=2, n3=2):
        """
        Scenario 7: Multi-level cascade fault attempt.

        A malicious Edge party corrupts its commitment during the
        Edge→Fog transition.  The fault is detected at the Fog boundary
        (commit-then-reveal check), the Edge level is isolated, and the
        Fog and Cloud levels remain fully operational — demonstrating
        containment.
        """
        self.reset_metrics()
        proto = HSPDZCloud([n1, n2, n3])

        # Compute a value at Edge
        x = proto.share_secret(99, 0)
        triple = proto.generate_triple(0)
        result = proto.multiply(x, proto.share_secret(1, 0), triple)

        ok_edge = proto.batch_verify([result], 0)

        # Edge→Fog transition: party 0 is corrupt (tampers after commitment)
        commit = proto.commit_transition(result, 1)
        fog_result, malicious_edge = proto.transition_level(
            result, 1, commit, corrupt_parties=[0]
        )

        # Fault must be detected at Fog boundary
        edge_fault_caught = malicious_edge is not None

        if edge_fault_caught:
            # Fog and Cloud are unaffected: perform Fog→Cloud cleanly
            # using a fresh honest value (Edge level isolated, restart from Fog)
            fog_val = proto.share_secret(99, 1)   # Fog re-issues honest value
            commit2 = proto.commit_transition(fog_val, 2)
            cloud_result, malicious_fog = proto.transition_level(fog_val, 2, commit2)

            upper_levels_operational = (malicious_fog is None and
                                        proto.reconstruct(cloud_result) == 99)
        else:
            upper_levels_operational = False

        return {
            'scenario': 'cascade_faults',
            'edge_fault_caught': edge_fault_caught,
            'malicious_edge_parties': malicious_edge,
            'upper_levels_operational': upper_levels_operational,
            'containment_demonstrated': edge_fault_caught and upper_levels_operational,
        }

    def scenario_6_ml_inference(self, n1=5, n2=3, n3=2, input_dim=4):
        """Scenario 6: Realistic ML inference (dot product)."""
        self.reset_metrics()
        proto = HSPDZCloud([n1, n2, n3])

        inputs = [proto.share_secret(np.random.randint(1, 100), 0) for _ in range(input_dim)]
        weights = [proto.share_secret(np.random.randint(1, 10), 0) for _ in range(input_dim)]

        triples = [proto.generate_triple(0) for _ in range(input_dim)]
        products = []
        total_lat = 0

        for i in range(input_dim):
            prod, lat = self.measure_latency(proto.multiply, inputs[i], weights[i], triples[i])
            products.append(prod)
            total_lat += lat

        acc = products[0]
        for p in products[1:]:
            acc = proto.add(acc, p)

        proto.batch_verify(products + [acc], 0)

        commit = proto.commit_transition(acc, 1)
        fog_r, _ = proto.transition_level(acc, 1, commit)
        commit2 = proto.commit_transition(fog_r, 2)
        cloud_r, _ = proto.transition_level(fog_r, 2, commit2)

        final = proto.reconstruct(cloud_r)
        expected = sum(proto.reconstruct(inputs[i]) * proto.reconstruct(weights[i]) for i in range(input_dim)) % proto.p

        return {
            'scenario': 'ml_inference',
            'latency_ms': total_lat,
            'comm_kb': proto.metrics['communication_bytes']/1024,
            'rounds': proto.metrics['rounds'],
            'correct': final == expected
        }

    def run_scalability_benchmark(self, n1_values=[3,5,7,9,10], n2=3, n3=2, depth=50):
        """Benchmark scalability across different Edge sizes."""
        results = []
        for n1 in n1_values:
            self.reset_metrics()
            proto = HSPDZCloud([n1, n2, n3])

            vals = [proto.share_secret(i+1, 0) for i in range(2)]
            triples = [proto.generate_triple(0) for _ in range(depth)]

            start = time.perf_counter()
            curr = vals[0]
            for d in range(depth):
                curr = proto.multiply(curr, vals[1] if d == 0 else curr, triples[d])
            end = time.perf_counter()

            results.append({
                'n1': n1,
                'latency_ms': (end - start) * 1000,
                'comm_kb': proto.metrics['communication_bytes'] / 1024,
                'rounds': proto.metrics['rounds']
            })
        return results


if __name__ == "__main__":
    print("H-SPDZ-Cloud Protocol Implementation v2.0")
    print(f"Security bits: {SECURITY_BITS}")
    print(f"Field: F_{P} (Mersenne prime, {FIELD_BYTES} bytes per element)")
    print("="*60)

    proto = HSPDZCloud([3, 2, 2])
    exp = HSPDZExperiments(proto)

    # Run all seven scenarios from the evaluation plan.
    scenarios = [
        exp.scenario_1_nominal(),
        exp.scenario_2_edge_fault(),
        exp.scenario_3_fog_transition_fault(),
        exp.scenario_4_cloud_fault(),
        exp.scenario_5_majority_corruption(),
        exp.scenario_6_ml_inference(),
        exp.scenario_7_cascade_faults(),
    ]

    for s in scenarios:
        print(s)

    # Scalability
    bench = exp.run_scalability_benchmark()
    print("\nScalability:")
    for b in bench:
        print(f"  n1={b['n1']}: {b['latency_ms']:.2f}ms, {b['comm_kb']:.2f}KB")
