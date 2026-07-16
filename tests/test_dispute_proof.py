"""
Regression tests for privacy-preserving transition disputes.
"""

from dataclasses import replace

import hspdz_dispute
import hspdz_vss
from hspdz_cloud_implementation import HSPDZCloud, rand_field, rand_commit_blind


def make_statement(n_next: int = 3):
    proto = HSPDZCloud([5, n_next, 2])
    shared = proto.share_secret(12345, 0)
    commit_data = proto.commit_transition(shared, 1)
    source_id = 1
    source_value = int(shared.shares[source_id])
    source_blind = int(commit_data["commitment_blinds"][source_id])

    subshares = [rand_field() for _ in range(n_next - 1)]
    subshares.append(source_value - sum(subshares))
    sub_blinds = [rand_commit_blind() for _ in range(n_next - 1)]
    sub_blinds.append((source_blind - sum(sub_blinds)) % hspdz_vss.curve_order)
    sub_commitments = [
        hspdz_vss.commit(subshares[j], sub_blinds[j]) for j in range(n_next)
    ]
    context = {
        "session_id": commit_data["session_id"],
        "level_id": 0,
        "next_level": 1,
        "transition_id": commit_data["transition_id"],
        "source_id": source_id,
        "n_next": n_next,
    }
    source_party = proto.levels[0][source_id]
    transcripts = []
    for j, commitment in enumerate(sub_commitments):
        transcripts.append(
            hspdz_dispute.create_signed_transcript(
                signing_key=source_party.signing_key,
                session_id=commit_data["session_id"],
                level_id=0,
                transition_id=commit_data["transition_id"],
                sender_id=source_id,
                receiver_id=j,
                sequence_number=j,
                commitment_id=f"{commit_data['transition_id']}:src{source_id}:recv{j}",
                payload_digest=hspdz_dispute.digest_transition_payload(
                    receiver_id=j,
                    commitment=commitment,
                ),
            )
        )
    proof = hspdz_dispute.prove_transition_consistency(
        context=context,
        source_commitment=commit_data["value_commitments"][source_id],
        sub_commitments=sub_commitments,
        source_value=source_value,
        source_blind=source_blind,
        subshares=subshares,
        sub_blinds=sub_blinds,
        signed_transcripts=transcripts,
    )
    return proto, source_party, context, commit_data, source_id, sub_commitments, transcripts, proof


def test_sigma_dispute_proof_accepts_valid_statement():
    proto, source_party, context, commit_data, source_id, sub_commitments, transcripts, proof = make_statement()
    assert all(
        hspdz_dispute.verify_signed_transcript(
            transcript,
            expected_public_key=source_party.verification_key,
        )
        for transcript in transcripts
    )
    assert hspdz_dispute.verify_transition_consistency_proof(
        context=context,
        source_commitment=commit_data["value_commitments"][source_id],
        sub_commitments=sub_commitments,
        signed_transcripts=transcripts,
        proof=proof,
    )
    assert proof.encoded_size() > 0


def test_sigma_dispute_proof_rejects_tampered_subcommitment():
    _, _, context, commit_data, source_id, sub_commitments, transcripts, proof = make_statement()
    tampered = list(sub_commitments)
    tampered[0] = hspdz_vss.commit(777, rand_commit_blind())
    assert not hspdz_dispute.verify_transition_consistency_proof(
        context=context,
        source_commitment=commit_data["value_commitments"][source_id],
        sub_commitments=tampered,
        signed_transcripts=transcripts,
        proof=proof,
    )


def test_signed_transcript_rejects_payload_change():
    _, source_party, _, _, _, _, transcripts, _ = make_statement()
    tampered = replace(transcripts[0], payload_digest="00" * 32)
    assert not hspdz_dispute.verify_signed_transcript(
        tampered,
        expected_public_key=source_party.verification_key,
    )


def test_transition_path_detects_invalid_sigma_fallback():
    proto = HSPDZCloud([3, 2, 2])
    shared = proto.share_secret(12345, 0)
    commit_data = proto.commit_transition(shared, 1)
    transitioned, malicious = proto.transition_level(shared, 1, commit_data, corrupt_parties=[1])
    assert transitioned is None
    assert malicious == [1]
    assert proto.metrics["transition_proof_failures"] == 1
    assert proto.metrics["transition_sigma_gen_ms"] > 0
    assert proto.metrics["transition_sigma_verify_ms"] > 0


def test_dispute_attribution_matrix_cases():
    expected = {
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
    for event, outcome in expected.items():
        assert hspdz_dispute.classify_dispute_event(event) == outcome


def test_malformed_commitment_encoding_rejected():
    try:
        hspdz_dispute.point_from_hex("00")
    except ValueError:
        return
    raise AssertionError("malformed commitment encoding was accepted")


if __name__ == "__main__":
    test_sigma_dispute_proof_accepts_valid_statement()
    test_sigma_dispute_proof_rejects_tampered_subcommitment()
    test_signed_transcript_rejects_payload_change()
    test_transition_path_detects_invalid_sigma_fallback()
    test_dispute_attribution_matrix_cases()
    test_malformed_commitment_encoding_rejected()
    print("Dispute proof tests passed")
