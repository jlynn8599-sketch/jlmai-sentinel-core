import hashlib
import hmac
import json
import math
from collections.abc import Mapping, Sequence
from typing import Any


VALID_STATUSES = {
    "PASS",
    "FAIL",
    "UNKNOWN",
    "NOT_CHECKED",
}


def _validate_json_value(value: Any) -> bool:
    """Accept only finite, unambiguous JSON-compatible values."""

    if value is None or isinstance(value, (str, bool, int)):
        return True

    if isinstance(value, float):
        return math.isfinite(value)

    if isinstance(value, list):
        return all(_validate_json_value(item) for item in value)

    if isinstance(value, Mapping):
        return all(
            isinstance(key, str) and _validate_json_value(item)
            for key, item in value.items()
        )

    return False


def compute_event_hash(event: Any) -> str:
    """
    Compute SHA-256 over the complete event, excluding only
    t5_evidence.event_hash.
    """

    if not isinstance(event, Mapping):
        raise ValueError("Event must be a mapping")

    if not _validate_json_value(event):
        raise ValueError("Event contains invalid JSON values")

    t5 = event.get("t5_evidence")

    if not isinstance(t5, Mapping):
        raise ValueError("Missing T5 evidence")

    payload = dict(event)
    t5_payload = dict(t5)
    t5_payload.pop("event_hash", None)
    payload["t5_evidence"] = t5_payload

    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")

    return hashlib.sha256(canonical).hexdigest()


def verify_t5_chain(
    events: Any,
    checkpoint: Mapping[str, Any] | None = None,
) -> str:
    """
    Verify ordered event hashes and predecessor links.

    Without a checkpoint, the chain must begin at sequence 0
    with a null previous_event_hash.

    With a checkpoint, the first event must immediately follow
    the externally trusted sequence and hash.

    Returns PASS, FAIL, UNKNOWN, or NOT_CHECKED.
    """

    if (
        not isinstance(events, Sequence)
        or isinstance(events, (str, bytes))
        or not events
    ):
        return "FAIL"

    if checkpoint is None:
        expected_sequence = 0
        expected_hash = None
    else:
        if not isinstance(checkpoint, Mapping):
            return "FAIL"

        sequence = checkpoint.get("sequence")
        event_hash = checkpoint.get("event_hash")

        if (
            isinstance(sequence, bool)
            or not isinstance(sequence, int)
            or sequence < 0
            or not isinstance(event_hash, str)
            or len(event_hash) != 64
        ):
            return "FAIL"

        if any(c not in "0123456789abcdefABCDEF" for c in event_hash):
            return "FAIL"

        expected_sequence = sequence + 1
        expected_hash = event_hash.lower()

    observed_statuses = []

    for event in events:
        if not isinstance(event, Mapping):
            return "FAIL"

        t5 = event.get("t5_evidence")

        if not isinstance(t5, Mapping):
            return "FAIL"

        status = t5.get("status")
        sequence = t5.get("sequence")
        event_hash = t5.get("event_hash")
        previous_hash = t5.get("previous_event_hash")

        if not isinstance(status, str) or status not in VALID_STATUSES:
            return "FAIL"

        if (
            isinstance(sequence, bool)
            or not isinstance(sequence, int)
            or sequence != expected_sequence
        ):
            return "FAIL"

        if not isinstance(event_hash, str) or len(event_hash) != 64:
            return "FAIL"

        if any(c not in "0123456789abcdefABCDEF" for c in event_hash):
            return "FAIL"

        if expected_hash is None:
            if previous_hash is not None:
                return "FAIL"
        else:
            if (
                not isinstance(previous_hash, str)
                or not hmac.compare_digest(
                    previous_hash.lower(),
                    expected_hash,
                )
            ):
                return "FAIL"

        try:
            calculated_hash = compute_event_hash(event)
        except (TypeError, ValueError):
            return "FAIL"

        if not hmac.compare_digest(
            calculated_hash,
            event_hash.lower(),
        ):
            return "FAIL"

        observed_statuses.append(status)
        expected_hash = calculated_hash
        expected_sequence += 1

    # Integrity verification cannot upgrade a non-PASS status.
    for status in ("FAIL", "UNKNOWN", "NOT_CHECKED"):
        if status in observed_statuses:
            return status

    return "PASS"
