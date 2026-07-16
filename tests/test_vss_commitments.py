"""
Regression tests for the H-SPDZ-Cloud Pedersen/VSS transition layer.
"""

import hspdz_vss
from hspdz_cloud_implementation import HSPDZCloud, rand_field


def test_pedersen_conservation_accepts_honest_resharing():
    proto = HSPDZCloud([3, 2, 2])
    shared = proto.share_secret(12345, 0)
    commit_data = proto.commit_transition(shared, 1)
    transitioned, malicious = proto.transition_level(shared, 1, commit_data)
    assert malicious is None
    assert transitioned is not None
    assert proto.reconstruct(transitioned) == 12345
    assert proto.verify_mac(transitioned)


def test_pedersen_conservation_rejects_modified_source_share():
    proto = HSPDZCloud([3, 2, 2])
    shared = proto.share_secret(12345, 0)
    commit_data = proto.commit_transition(shared, 1)
    transitioned, malicious = proto.transition_level(shared, 1, commit_data, corrupt_parties=[1])
    assert transitioned is None
    assert malicious == [1]
    assert proto.metrics["transition_proof_failures"] == 1


def test_commitment_binding_to_opening():
    value = rand_field()
    blind = hspdz_vss.random_blind()
    commitment = hspdz_vss.commit(value, blind)
    assert hspdz_vss.equal(commitment, hspdz_vss.commit(value, blind))
    assert not hspdz_vss.equal(commitment, hspdz_vss.commit(value + 1, blind))
    assert not hspdz_vss.equal(commitment, hspdz_vss.commit(value, blind + 1))


if __name__ == "__main__":
    test_pedersen_conservation_accepts_honest_resharing()
    test_pedersen_conservation_rejects_modified_source_share()
    test_commitment_binding_to_opening()
    print("VSS commitment tests passed")
