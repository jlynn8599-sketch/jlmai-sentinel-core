"""Founder public-key registry for JLMAI Sentinel.

This module never generates, imports, or stores private keys.
Initial trust requires an independently verified SHA-256 fingerprint.
"""

import base64
import hashlib
import json
import os
import stat
from typing import Any


SCHEMA_VERSION = 1
ALGORITHM = "Ed25519"
MAX_REGISTRY_BYTES = 4096


class RegistryError(Exception):
    """Base exception for root registry errors."""


class RegistryExistsError(RegistryError):
    """Raised when enrollment would overwrite an existing registry."""


class RegistryTrustError(RegistryError):
    """Raised when the registry does not match the trusted fingerprint."""


def public_key_fingerprint(public_key_bytes: bytes) -> str:
    """Return the lowercase SHA-256 fingerprint of a raw Ed25519 public key."""
    if not isinstance(public_key_bytes, bytes) or len(public_key_bytes) != 32:
        raise ValueError("Ed25519 public key must contain exactly 32 bytes")

    return hashlib.sha256(public_key_bytes).hexdigest()


def build_root_record(
    public_key_bytes: bytes,
    expected_fingerprint: str,
) -> dict[str, Any]:
    """Build a root record only when its key matches an independently pinned fingerprint."""
    actual = public_key_fingerprint(public_key_bytes)

    if not isinstance(expected_fingerprint, str):
        raise RegistryTrustError("A trusted fingerprint is required")

    if actual != expected_fingerprint.lower():
        raise RegistryTrustError("Public key does not match trusted fingerprint")

    return {
        "schema_version": SCHEMA_VERSION,
        "algorithm": ALGORITHM,
        "key_id": actual,
        "public_key": base64.b64encode(public_key_bytes).decode("ascii"),
        "status": "ACTIVE",
    }


def _reject_duplicate_keys(pairs):
    result = {}

    for key, value in pairs:
        if key in result:
            raise RegistryError(f"Duplicate JSON key: {key}")
        result[key] = value

    return result


def validate_root_record(
    record: Any,
    expected_fingerprint: str,
) -> bytes:
    """Validate exact registry structure and its independently pinned identity."""
    if not isinstance(record, dict):
        raise RegistryError("Registry must be a JSON object")

    required = {
        "schema_version",
        "algorithm",
        "key_id",
        "public_key",
        "status",
    }

    if set(record) != required:
        raise RegistryError("Registry fields do not match required schema")

    if record["schema_version"] != SCHEMA_VERSION:
        raise RegistryError("Unsupported registry schema version")

    if record["algorithm"] != ALGORITHM:
        raise RegistryError("Unsupported root-key algorithm")

    if record["status"] != "ACTIVE":
        raise RegistryTrustError("Founder root key is not active")

    if not isinstance(record["public_key"], str):
        raise RegistryError("Public key must be a Base64 string")

    try:
        public_key = base64.b64decode(
            record["public_key"],
            validate=True,
        )
    except (ValueError, base64.binascii.Error) as exc:
        raise RegistryError("Invalid public-key Base64") from exc

    actual_fingerprint = public_key_fingerprint(public_key)

    if not isinstance(record["key_id"], str):
        raise RegistryError("Invalid key identifier")

    if actual_fingerprint != record["key_id"]:
        raise RegistryTrustError("Public key does not match registry key ID")

    if not isinstance(expected_fingerprint, str):
        raise RegistryTrustError("Trusted fingerprint is required")

    if actual_fingerprint != expected_fingerprint.lower():
        raise RegistryTrustError("Registry does not match trusted fingerprint")

    return public_key


def enroll_initial_root(
    path: str,
    public_key_bytes: bytes,
    expected_fingerprint: str,
) -> dict[str, Any]:
    """Create a new registry without overwriting an existing file."""
    record = build_root_record(
        public_key_bytes,
        expected_fingerprint,
    )

    directory = os.path.dirname(os.path.abspath(path))

    if not os.path.isdir(directory):
        raise RegistryError("Registry parent directory does not exist")

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL

    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise RegistryExistsError("Registry already exists") from exc
    except OSError as exc:
        raise RegistryError("Unable to create registry") from exc

    try:
        payload = json.dumps(
            record,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")

        with os.fdopen(fd, "wb") as handle:
            fd = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(path)
        except OSError:
            pass
        raise

    return record


def load_root_registry(
    path: str,
    expected_fingerprint: str,
) -> dict[str, Any]:
    """Load and validate a registry without following symlinks."""
    flags = os.O_RDONLY

    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise RegistryError("Unable to safely open registry") from exc

    try:
        file_stat = os.fstat(fd)

        if not stat.S_ISREG(file_stat.st_mode):
            raise RegistryError("Registry must be a regular file")

        if file_stat.st_size > MAX_REGISTRY_BYTES:
            raise RegistryError("Registry exceeds maximum allowed size")

        with os.fdopen(fd, "rb") as handle:
            fd = -1
            raw = handle.read(MAX_REGISTRY_BYTES + 1)

        if len(raw) > MAX_REGISTRY_BYTES:
            raise RegistryError("Registry exceeds maximum allowed size")

    finally:
        if fd >= 0:
            os.close(fd)

    try:
        record = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except RegistryError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RegistryError("Registry is not valid UTF-8 JSON") from exc

    validate_root_record(record, expected_fingerprint)
    return record
