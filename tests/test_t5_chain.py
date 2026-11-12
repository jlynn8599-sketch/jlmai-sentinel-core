import pytest

from sentinel.evidence.t5_chain import (
    compute_event_hash,
    verify_t5_chain,
)


def make_event(sequence, previous_hash=None, status="PASS"):
    event = {
        "event_id": f"event-{sequence}",
        "guard_id": "game_guard",
        "device_id": "device-test",
        "timestamp": "2026-11-11T12:00:00Z",
        "policy_version": "1.0.0",
        "t1_identity": {"status": "PASS"},
        "t2_scope": {"status": "PASS"},
        "t3_integrity": {"status": "PASS"},
        "t4_egress": {"status": "PASS"},
        "t5_evidence": {
            "status": status,
            "sequence": sequence,
            "event_hash": "0" * 64,
            "previous_event_hash": previous_hash,
        },
        "decision": "ALLOW",
        "decision_reason": "All checks passed",
    }
    event["t5_evidence"]["event_hash"] = compute_event_hash(event)
    return event


def test_valid_genesis_event_passes():
    assert verify_t5_chain([make_event(0)]) == "PASS"


def test_valid_two_event_chain_passes():
    first = make_event(0)
    second = make_event(1, first["t5_evidence"]["event_hash"])
    assert verify_t5_chain([first, second]) == "PASS"


def test_modified_event_is_rejected():
    event = make_event(0)
    event["decision"] = "DENY"
    assert verify_t5_chain([event]) == "FAIL"


def test_broken_previous_hash_is_rejected():
    first = make_event(0)
    second = make_event(1, "f" * 64)
    assert verify_t5_chain([first, second]) == "FAIL"


def test_repeated_sequence_is_rejected():
    assert verify_t5_chain([make_event(0), make_event(0)]) == "FAIL"


def test_out_of_order_sequence_is_rejected():
    first = make_event(0)
    second = make_event(2, first["t5_evidence"]["event_hash"])
    assert verify_t5_chain([first, second]) == "FAIL"


def test_unknown_status_is_preserved():
    assert verify_t5_chain([make_event(0, status="UNKNOWN")]) == "UNKNOWN"


def test_not_checked_is_never_upgraded():
    assert verify_t5_chain([make_event(0, status="NOT_CHECKED")]) == "NOT_CHECKED"


def test_invalid_event_fails_closed():
    assert verify_t5_chain([None]) == "FAIL"


def test_empty_chain_fails_closed():
    assert verify_t5_chain([]) == "FAIL"


def test_trusted_checkpoint_accepts_continuation():
    first = make_event(0)
    second = make_event(1, first["t5_evidence"]["event_hash"])
    checkpoint = {
        "sequence": 0,
        "event_hash": first["t5_evidence"]["event_hash"],
    }
    assert verify_t5_chain([second], checkpoint) == "PASS"


def test_checkpoint_rejects_replayed_event():
    first = make_event(0)
    checkpoint = {
        "sequence": 0,
        "event_hash": first["t5_evidence"]["event_hash"],
    }
    assert verify_t5_chain([first], checkpoint) == "FAIL"


def test_invalid_checkpoint_fails_closed():
    assert verify_t5_chain(
        [make_event(0)],
        {"sequence": True, "event_hash": "0" * 64},
    ) == "FAIL"


@pytest.mark.parametrize("bad_status", [[], {}, None, 123])
def test_invalid_status_fails_closed(bad_status):
    event = make_event(0)
    event["t5_evidence"]["status"] = bad_status
    assert verify_t5_chain([event]) == "FAIL"
