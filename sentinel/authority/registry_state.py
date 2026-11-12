"""Authenticated and rollback-aware Sentinel root registry state."""

import base64
import hashlib
import json
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


DOMAIN = b"JLMAI-SENTINEL-ROOT-STATE-V1\x00"
SCHEMA_VERSION = 1
ALGORITHM = "Ed25519"
VALID_STATUSES = {"ACTIVE", "REVOKED"}


class RegistryStateError(Exception):
    """Base error for authenticated registry state."""


class RegistryStateTrustError(RegistryStateError):
    """Raised when identity or signature verification fails."""


class RegistryRollbackError(RegistryStateError):
    """Raised when a registry sequence is stale or repeated."""


def canonical_state_bytes(state: Mapping[str, Any]) -> bytes:
    """Serialize signed state deterministically."""
    if not isinstance(state, Mapping):
        raise RegistryStateError("State must be a mapping")

    try:
        return json.dumps(
            dict(state),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise RegistryStateError("Invalid state serialization") from exc


def verify_registry_state(
    envelope: Mapping[str, Any],
    trusted_fingerprint: str,
    last_seen_sequence: int,
) -> dict[str, Any]:
    """Verify identity, signed status, and monotonic sequence.

    last_seen_sequence MUST come from independently protected,
    rollback-resistant storage. This function does not store it.
    """
    required = {
        "schema_version",
        "algorithm",
        "key_id",
        "public_key",
        "sequence",
        "status",
        "signature",
    }

    if not isinstance(envelope, Mapping):
        raise RegistryStateError("Envelope must be a mapping")

    if set(envelope) != required:
        raise RegistryStateError("Unexpected registry-state fields")

    if type(envelope["schema_version"]) is not int:
        raise RegistryStateError("Invalid schema version type")

    if envelope["schema_version"] != SCHEMA_VERSION:
        raise RegistryStateError("Unsupported schema version")

    if not isinstance(envelope["algorithm"], str):
        raise RegistryStateError("Invalid algorithm type")

    if envelope["algorithm"] != ALGORITHM:
        raise RegistryStateError("Unsupported algorithm")

    sequence = envelope["sequence"]

    if type(sequence) is not int or sequence < 1:
        raise RegistryStateError("Invalid sequence number")

    if type(last_seen_sequence) is not int or last_seen_sequence < 0:
        raise RegistryStateError("Invalid trusted sequence checkpoint")

    if sequence <= last_seen_sequence:
        raise RegistryRollbackError("Stale or repeated registry sequence")

    if not isinstance(envelope["status"], str):
        raise RegistryStateError("Invalid registry status type")

    if envelope["status"] not in VALID_STATUSES:
        raise RegistryStateError("Invalid registry status")

    if not isinstance(envelope["public_key"], str):
        raise RegistryStateError("Public key must be Base64 text")

    if not isinstance(envelope["key_id"], str):
        raise RegistryStateError("Invalid key identifier")

    if not isinstance(trusted_fingerprint, str):
        raise RegistryStateTrustError("Trusted fingerprint required")

    if len(trusted_fingerprint) != 64:
        raise RegistryStateTrustError("Invalid trusted fingerprint")

    try:
        bytes.fromhex(trusted_fingerprint)
    except ValueError as exc:
        raise RegistryStateTrustError("Invalid trusted fingerprint") from exc

    try:
        public_key_bytes = base64.b64decode(
            envelope["public_key"],
            validate=True,
        )
    except (TypeError, ValueError, base64.binascii.Error) as exc:
        raise RegistryStateError("Invalid public-key encoding") from exc

    if len(public_key_bytes) != 32:
        raise RegistryStateError("Invalid Ed25519 public key length")

    actual_fingerprint = hashlib.sha256(public_key_bytes).hexdigest()

    if actual_fingerprint != envelope["key_id"]:
        raise RegistryStateTrustError("Key identifier mismatch")

    if actual_fingerprint != trusted_fingerprint.lower():
        raise RegistryStateTrustError("Untrusted root public key")

    if not isinstance(envelope["signature"], str):
        raise RegistryStateError("Signature must be Base64 text")

    try:
        signature = base64.b64decode(
            envelope["signature"],
            validate=True,
        )
    except (ValueError, base64.binascii.Error) as exc:
        raise RegistryStateError("Invalid signature encoding") from exc

    if len(signature) != 64:
        raise RegistryStateError("Invalid Ed25519 signature length")

    signed_fields = {
        key: value
        for key, value in envelope.items()
        if key != "signature"
    }

    message = DOMAIN + canonical_state_bytes(signed_fields)

    try:
        Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(
            signature,
            message,
        )
    except InvalidSignature as exc:
        raise RegistryStateTrustError(
            "Registry-state signature verification failed"
        ) from exc

    return dict(envelope)
