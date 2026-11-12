import base64

import pytest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel.authority.policy_signature import (
    SIGNATURE_DOMAIN,
    canonical_policy_bytes,
    verify_policy_signature,
)


def make_test_key():
    private_key = Ed25519PrivateKey.generate()

    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    return private_key, public_bytes


def sign_test_policy(private_key, policy):
    message = SIGNATURE_DOMAIN + canonical_policy_bytes(policy)
    signature = private_key.sign(message)
    return base64.b64encode(signature).decode("ascii")


def test_valid_policy_signature_is_accepted():
    private_key, public_bytes = make_test_key()

    policy = {
        "policy_id": "sentinel-test",
        "policy_version": "1.0.0",
        "rules": ["deny_by_default"],
    }

    signature = sign_test_policy(private_key, policy)

    assert verify_policy_signature(
        public_bytes, policy, signature
    ) is True


def test_modified_policy_is_rejected():
    private_key, public_bytes = make_test_key()

    original = {
        "policy_id": "sentinel-test",
        "policy_version": "1.0.0",
        "rules": ["deny_by_default"],
    }

    signature = sign_test_policy(private_key, original)

    modified = {
        **original,
        "rules": ["allow_everything"],
    }

    with pytest.raises(InvalidSignature):
        verify_policy_signature(public_bytes, modified, signature)


def test_wrong_public_key_is_rejected():
    signing_key, _ = make_test_key()
    _, wrong_public_key = make_test_key()

    policy = {"policy_id": "sentinel-test"}

    signature = sign_test_policy(signing_key, policy)

    with pytest.raises(InvalidSignature):
        verify_policy_signature(wrong_public_key, policy, signature)


def test_malformed_public_key_is_rejected():
    with pytest.raises(ValueError):
        verify_policy_signature(b"short", {}, "ZmFrZQ==")


def test_malformed_signature_is_rejected():
    _, public_bytes = make_test_key()

    with pytest.raises(ValueError):
        verify_policy_signature(public_bytes, {}, "not-valid-base64!")


def test_canonical_serialization_is_order_independent():
    first = {"a": 1, "b": 2}
    second = {"b": 2, "a": 1}

    assert canonical_policy_bytes(first) == canonical_policy_bytes(second)
