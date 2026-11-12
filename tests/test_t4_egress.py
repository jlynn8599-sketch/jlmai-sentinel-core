import pytest

from sentinel.authorization.t4_egress import evaluate_t4_egress


def evidence(status="PASS", allowed=None, observed=None):
    return {
        "status": status,
        "allowed_destinations": (
            ["local"] if allowed is None else allowed
        ),
        "observed_destinations": (
            ["local"] if observed is None else observed
        ),
    }


def test_authorized_destination_passes():
    assert evaluate_t4_egress(evidence()) == "PASS"


def test_unauthorized_destination_fails():
    item = evidence(observed=["local", "unknown_server"])
    assert evaluate_t4_egress(item) == "FAIL"


def test_empty_observed_list_passes_when_no_egress_occurred():
    item = evidence(allowed=["local"], observed=[])
    assert evaluate_t4_egress(item) == "PASS"


def test_empty_allowlist_rejects_observed_destination():
    item = evidence(allowed=[], observed=["external"])
    assert evaluate_t4_egress(item) == "FAIL"


def test_unknown_never_becomes_pass():
    item = evidence(status="UNKNOWN")
    assert evaluate_t4_egress(item) == "UNKNOWN"


def test_not_checked_never_becomes_pass():
    item = evidence(status="NOT_CHECKED")
    assert evaluate_t4_egress(item) == "NOT_CHECKED"


def test_explicit_failure_remains_failure():
    item = evidence(status="FAIL")
    assert evaluate_t4_egress(item) == "FAIL"


@pytest.mark.parametrize("bad_evidence", [
    None,
    {},
    {"status": "INVALID"},
    {"status": "PASS", "allowed_destinations": "local",
     "observed_destinations": ["local"]},
    {"status": "PASS", "allowed_destinations": ["local"],
     "observed_destinations": "local"},
    {"status": "PASS", "allowed_destinations": ["local"],
     "observed_destinations": [""]},
])
def test_malformed_evidence_fails_closed(bad_evidence):
    assert evaluate_t4_egress(bad_evidence) == "FAIL"


@pytest.mark.parametrize("bad_status", [
    [],
    {},
    None,
    123,
])
def test_non_string_status_fails_closed(bad_status):
    item = evidence()
    item["status"] = bad_status
    assert evaluate_t4_egress(item) == "FAIL"
