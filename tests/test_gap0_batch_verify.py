"""
Regression tests for the corrected masked batch MAC verification.
"""

from hspdz_cloud_implementation import HSPDZCloud


def assert_raises(expected_message, fn):
    try:
        fn()
    except ValueError as exc:
        assert expected_message in str(exc)
        return
    raise AssertionError("expected ValueError was not raised")


def test_masked_batch_verify_accepts_valid_values():
    proto = HSPDZCloud([5, 3, 2])
    values = [proto.share_secret(10, 0), proto.share_secret(20, 0)]

    assert proto.batch_verify(values, 0)


def test_masked_batch_verify_rejects_invalid_mac():
    proto = HSPDZCloud([5, 3, 2])
    value = proto.share_secret(10, 0)
    value.mac_shares[1] = (value.mac_shares[1] + 1) % proto.p

    assert not proto.batch_verify([value], 0)


def test_authenticated_mask_reuse_is_rejected():
    proto = HSPDZCloud([5, 3, 2])
    value = proto.share_secret(10, 0)
    mask = proto.generate_authenticated_mask(0)

    assert proto.batch_verify([value], 0, mask=mask)
    assert_raises("mask reuse", lambda: proto.batch_verify([value], 0, mask=mask))


def test_external_coefficients_require_prior_binding():
    proto = HSPDZCloud([5, 3, 2])
    value = proto.share_secret(10, 0)

    assert_raises("prior batch binding", lambda: proto.batch_verify([value], 0, coefficients=[1]))


def test_stale_binding_detects_state_changed_after_challenge():
    proto = HSPDZCloud([5, 3, 2])
    value = proto.share_secret(10, 0)
    binding = proto.bind_batch_state([value], 0, session_id="session-gap0", batch_id=1)
    coefficients = proto.derive_batch_challenges(binding)

    value.shares[0] = (value.shares[0] + 1) % proto.p
    assert_raises(
        "state changed",
        lambda: proto.batch_verify([value], 0, binding=binding, coefficients=coefficients),
    )


def test_commit_then_open_rejects_rushing_check_share_change():
    proto = HSPDZCloud([5, 3, 2])
    value = proto.share_secret(10, 0)

    assert not proto.batch_verify([value], 0, _tamper_check_share_for_test=True)


if __name__ == "__main__":
    test_masked_batch_verify_accepts_valid_values()
    test_masked_batch_verify_rejects_invalid_mac()
    test_authenticated_mask_reuse_is_rejected()
    test_external_coefficients_require_prior_binding()
    test_stale_binding_detects_state_changed_after_challenge()
    test_commit_then_open_rejects_rushing_check_share_change()
    print("Gap 0 masked batch verification tests passed")
