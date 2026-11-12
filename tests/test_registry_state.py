import base64
import hashlib

import pytest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel.authority.registry_state import (
    DOMAIN,
    RegistryRollbackError,
    RegistryStateError,
    RegistryStateTrustError,
    canonical_state_bytes,
    verify_registry_state,
)


def make_signed_state(status="ACTIVE", sequence=1):
    private_key = Ed25519PrivateKey.generate()

    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    fingerprint = hashlib.sha256(public_bytes).hexdigest()

    state = {
        "schema_version": 1,
        "algorithm": "Ed25519",
        "key_id": fingerprint,
        "public_key": base64.b64encode(public_bytes).decode("ascii"),
        "sequence": sequence,
        "status": status,
    }

    signature = private_key.sign(
        DOMAIN + canonical_state_bytes(state)
    )

    envelope = {
        **state,
        "signature": base64.b64encode(signature).decode("ascii"),
    }

    return envelope, fingerprint


def test_valid_active_state_is_accepted():
    envelope, fingerprint = make_signed_state()

    result = verify_registry_state(
        envelope,
        fingerprint,
        last_seen_sequence=0,
    )

    assert result["status"] == "ACTIVE"
    assert result["sequence"] == 1


def test_valid_revoked_state_is_accepted_as_revoked():
    envelope, fingerprint = make_signed_state(status="REVOKED")

    result = verify_registry_state(
        envelope,
        fingerprint,
        last_seen_sequence=0,
    )

    assert result["status"] == "REVOKED"


def test_modified_status_invalidates_signature():
    envelope, fingerprint = make_signed_state()

    envelope["status"] = "REVOKED"

    with pytest.raises(RegistryStateTrustError):
        verify_registry_state(envelope, fingerprint, 0)


def test_modified_sequence_invalidates_signature():
    envelope, fingerprint = make_signed_state(sequence=1)

    envelope["sequence"] = 2

    with pytest.raises(RegistryStateTrustError):
        verify_registry_state(envelope, fingerprint, 0)


def test_repeated_sequence_is_rejected():
    envelope, fingerprint = make_signed_state(sequence=4)

    with pytest.raises(RegistryRollbackError):
        verify_registry_state(envelope, fingerprint, 4)


def test_older_sequence_is_rejected():
    envelope, fingerprint = make_signed_state(sequence=3)

    with pytest.raises(RegistryRollbackError):
        verify_registry_state(envelope, fingerprint, 5)


def test_wrong_trusted_fingerprint_is_rejected():
    envelope, _ = make_signed_state()

    with pytest.raises(RegistryStateTrustError):
        verify_registry_state(envelope, "0" * 64, 0)


def test_modified_public_key_is_rejected():
    envelope, fingerprint = make_signed_state()

    replacement = Ed25519PrivateKey.generate().public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    envelope["public_key"] = base64.b64encode(
        replacement
    ).decode("ascii")

    with pytest.raises(RegistryStateTrustError):
        verify_registry_state(envelope, fingerprint, 0)


def test_boolean_sequence_is_rejected():
    envelope, fingerprint = make_signed_state()

    envelope["sequence"] = True

    with pytest.raises(RegistryStateError):
        verify_registry_state(envelope, fingerprint, 0)


def test_boolean_schema_version_is_rejected():
    envelope, fingerprint = make_signed_state()

    envelope["schema_version"] = True

    with pytest.raises(RegistryStateError):
        verify_registry_state(envelope, fingerprint, 0)


def test_invalid_status_is_rejected():
    envelope, fingerprint = make_signed_state()

    envelope["status"] = "UNKNOWN"

    with pytest.raises(RegistryStateError):
        verify_registry_state(envelope, fingerprint, 0)


def test_non_string_status_is_rejected_cleanly():
    envelope, fingerprint = make_signed_state()
    envelope["status"] = ["ACTIVE"]

    with pytest.raises(RegistryStateError):
        verify_registry_state(envelope, fingerprint, 0)


def test_non_string_signature_is_rejected_cleanly():
    envelope, fingerprint = make_signed_state()
    envelope["signature"] = ["not-a-signature"]

    with pytest.raises(RegistryStateError):
        verify_registry_state(envelope, fingerprint, 0)


def test_non_string_public_key_is_rejected_cleanly():
    envelope, fingerprint = make_signed_state()
    envelope["public_key"] = ["not-a-public-key"]

    with pytest.raises(RegistryStateError):
        verify_registry_state(envelope, fingerprint, 0)
