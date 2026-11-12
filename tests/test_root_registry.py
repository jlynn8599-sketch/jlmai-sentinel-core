import os
import base64

import pytest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel.authority.root_registry import (
    RegistryError,
    RegistryExistsError,
    RegistryTrustError,
    enroll_initial_root,
    load_root_registry,
    public_key_fingerprint,
    validate_root_record,
)


def make_test_key():
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return public


def test_fingerprint_is_deterministic():
    public = make_test_key()
    assert public_key_fingerprint(public) == public_key_fingerprint(public)


def test_initial_enrollment(tmp_path):
    public = make_test_key()
    fingerprint = public_key_fingerprint(public)
    path = str(tmp_path / "root.json")

    record = enroll_initial_root(path, public, fingerprint)

    assert record["key_id"] == fingerprint
    assert record["status"] == "ACTIVE"
    assert os.stat(path).st_mode & 0o777 == 0o600


def test_wrong_fingerprint_rejects_enrollment(tmp_path):
    public = make_test_key()
    path = str(tmp_path / "root.json")

    with pytest.raises(RegistryTrustError):
        enroll_initial_root(path, public, "0" * 64)

    assert not os.path.exists(path)


def test_existing_registry_cannot_be_overwritten(tmp_path):
    public = make_test_key()
    fingerprint = public_key_fingerprint(public)
    path = str(tmp_path / "root.json")

    enroll_initial_root(path, public, fingerprint)

    with pytest.raises(RegistryExistsError):
        enroll_initial_root(path, public, fingerprint)


def test_valid_registry_loads(tmp_path):
    public = make_test_key()
    fingerprint = public_key_fingerprint(public)
    path = str(tmp_path / "root.json")

    enroll_initial_root(path, public, fingerprint)

    record = load_root_registry(path, fingerprint)
    assert record["key_id"] == fingerprint


def test_wrong_trusted_fingerprint_rejects_registry(tmp_path):
    public = make_test_key()
    fingerprint = public_key_fingerprint(public)
    path = str(tmp_path / "root.json")

    enroll_initial_root(path, public, fingerprint)

    with pytest.raises(RegistryTrustError):
        load_root_registry(path, "0" * 64)


def test_modified_key_id_is_rejected(tmp_path):
    public = make_test_key()
    fingerprint = public_key_fingerprint(public)
    path = str(tmp_path / "root.json")

    enroll_initial_root(path, public, fingerprint)

    with open(path, encoding="utf-8") as handle:
        record = __import__("json").load(handle)

    record["key_id"] = "0" * 64

    with open(path, "w", encoding="utf-8") as handle:
        __import__("json").dump(record, handle)

    with pytest.raises(RegistryTrustError):
        load_root_registry(path, fingerprint)


def test_duplicate_json_keys_are_rejected():
    from sentinel.authority.root_registry import _reject_duplicate_keys

    with pytest.raises(RegistryError):
        _reject_duplicate_keys([
            ("status", "ACTIVE"),
            ("status", "REVOKED"),
        ])


def test_revoked_record_is_rejected():
    public = make_test_key()
    fingerprint = public_key_fingerprint(public)

    record = {
        "schema_version": 1,
        "algorithm": "Ed25519",
        "key_id": fingerprint,
        "public_key": base64.b64encode(public).decode("ascii"),
        "status": "REVOKED",
    }

    with pytest.raises(RegistryTrustError):
        validate_root_record(record, fingerprint)
