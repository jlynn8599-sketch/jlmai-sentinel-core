from collections.abc import Mapping
from typing import Any


VALID_STATUSES = {
    "PASS",
    "FAIL",
    "UNKNOWN",
    "NOT_CHECKED",
}


def evaluate_t4_egress(evidence: Any) -> str:
    """
    Evaluate T4 egress evidence.

    Returns:
        PASS        Only when all observed destinations are authorized.
        FAIL        For malformed evidence or unauthorized destinations.
        UNKNOWN     When verification is explicitly unknown.
        NOT_CHECKED When verification was not performed.

    This function never converts UNKNOWN or NOT_CHECKED into PASS.
    """

    if not isinstance(evidence, Mapping):
        return "FAIL"

    status = evidence.get("status")

    if not isinstance(status, str):
        return "FAIL"

    if status not in VALID_STATUSES:
        return "FAIL"

    if status != "PASS":
        return status

    allowed = evidence.get("allowed_destinations")
    observed = evidence.get("observed_destinations")

    if not isinstance(allowed, list):
        return "FAIL"

    if not isinstance(observed, list):
        return "FAIL"

    if any(
        not isinstance(item, str) or not item.strip()
        for item in allowed + observed
    ):
        return "FAIL"

    allowed_set = set(allowed)
    observed_set = set(observed)

    if not observed_set.issubset(allowed_set):
        return "FAIL"

    return "PASS"
