import base64
import hashlib

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel.evidence.checkpoint import (
    DOMAIN,
    CheckpointError,
    CheckpointRollbackError,
    CheckpointTrustError,
    canonical_checkpoint_bytes,
    verify_checkpoint,
)


GUARD_ID = "game_guard"


def make_checkpoint(private_key, sequence=0, previous=None):
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    fields = {
        "schema_version": 1,
        "algorithm": "Ed25519",
        "key_id": hashlib.sha256(public_bytes).hexdigest(),
        "public_key": base64.b64encode(public_bytes).decode("ascii"),
        "guard_id": GUARD_ID,
        "sequence": sequence,
        "event_hash": hashlib.sha256(
            f"event-{sequence}".encode()
        ).hexdigest(),
        "previous_checkpoint_hash": previous,
    }

    signature = private_key.sign(
        DOMAIN + canonical_checkpoint_bytes(fields)
    )

    return {
        **fields,
        "signature": base64.b64encode(signature).decode("ascii"),
    }


def trusted_fingerprint(private_key):
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(public_bytes).hexdigest()


def test_valid_initial_checkpoint_passes():
    key = Ed25519PrivateKey.generate()
    envelope = make_checkpoint(key)

    result = verify_checkpoint(
        envelope,
        trusted_fingerprint(key),
        GUARD_ID,
    )

    assert result["sequence"] == 0
    assert len(result["checkpoint_hash"]) == 64


def test_modified_event_hash_is_rejected():
    key = Ed25519PrivateKey.generate()
    envelope = make_checkpoint(key)
    envelope["event_hash"] = "a" * 64

    with pytest.raises(CheckpointTrustError):
        verify_checkpoint(envelope, trusted_fingerprint(key), GUARD_ID)


def test_wrong_signing_fingerprint_is_rejected():
    key = Ed25519PrivateKey.generate()
    other_key = Ed25519PrivateKey.generate()
    envelope = make_checkpoint(key)

    with pytest.raises(CheckpointTrustError):
        verify_checkpoint(
            envelope,
            trusted_fingerprint(other_key),
            GUARD_ID,
        )


def test_wrong_guard_identity_is_rejected():
    key = Ed25519PrivateKey.generate()
    envelope = make_checkpoint(key)

    with pytest.raises(CheckpointTrustError):
        verify_checkpoint(
            envelope,
            trusted_fingerprint(key),
            "mobile_guard",
        )


def test_replayed_checkpoint_is_rejected():
    key = Ed25519PrivateKey.generate()
    envelope = make_checkpoint(key)

    anchor = {
        "sequence": 0,
        "checkpoint_hash": "b" * 64,
    }

    with pytest.raises(CheckpointRollbackError):
        verify_checkpoint(
            envelope,
            trusted_fingerprint(key),
            GUARD_ID,
            anchor,
        )


def test_checkpoint_must_extend_trusted_predecessor():
    key = Ed25519PrivateKey.generate()
    envelope = make_checkpoint(key, sequence=2, previous="a" * 64)

    anchor = {
        "sequence": 1,
        "checkpoint_hash": "b" * 64,
    }

    with pytest.raises(CheckpointRollbackError):
        verify_checkpoint(
            envelope,
            trusted_fingerprint(key),
            GUARD_ID,
            anchor,
        )


def test_valid_checkpoint_continuation_passes():
    key = Ed25519PrivateKey.generate()
    first = make_checkpoint(key)

    first_result = verify_checkpoint(
        first,
        trusted_fingerprint(key),
        GUARD_ID,
    )

    second = make_checkpoint(
        key,
        sequence=1,
        previous=first_result["checkpoint_hash"],
    )

    second_result = verify_checkpoint(
        second,
        trusted_fingerprint(key),
        GUARD_ID,
        {
            "sequence": first_result["sequence"],
            "checkpoint_hash": first_result["checkpoint_hash"],
        },
    )

    assert second_result["sequence"] == 1


def test_boolean_sequence_is_rejected():
    key = Ed25519PrivateKey.generate()
    envelope = make_checkpoint(key, sequence=1)
    envelope["sequence"] = True

    with pytest.raises(CheckpointError):
        verify_checkpoint(envelope, trusted_fingerprint(key), GUARD_ID)


def test_unknown_fields_are_rejected():
    key = Ed25519PrivateKey.generate()
    envelope = make_checkpoint(key)
    envelope["unexpected"] = "value"

    with pytest.raises(CheckpointError):
        verify_checkpoint(envelope, trusted_fingerprint(key), GUARD_ID)
