"""Verify independently authenticated SENTINEL evidence checkpoints."""

import base64
import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


DOMAIN = b"JLMAI-SENTINEL-EVIDENCE-CHECKPOINT-V1\x00"
SCHEMA_VERSION = 1
ALGORITHM = "Ed25519"
HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")

REQUIRED_FIELDS = {
    "schema_version",
    "algorithm",
    "key_id",
    "public_key",
    "guard_id",
    "sequence",
    "event_hash",
    "previous_checkpoint_hash",
    "signature",
}


class CheckpointError(Exception):
    """Base checkpoint verification error."""


class CheckpointTrustError(CheckpointError):
    """Checkpoint identity or signature is not trusted."""


class CheckpointRollbackError(CheckpointError):
    """Checkpoint is stale or does not extend the trusted anchor."""


def canonical_checkpoint_bytes(payload: Mapping[str, Any]) -> bytes:
    """Serialize checkpoint fields deterministically."""
    if not isinstance(payload, Mapping):
        raise CheckpointError("Payload must be a mapping")

    try:
        return json.dumps(
            dict(payload),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise CheckpointError("Invalid checkpoint serialization") from exc


def checkpoint_digest(envelope: Mapping[str, Any]) -> str:
    """Hash the complete checkpoint envelope, including its signature."""
    if not isinstance(envelope, Mapping) or set(envelope) != REQUIRED_FIELDS:
        raise CheckpointError("Invalid checkpoint fields")

    return hashlib.sha256(
        DOMAIN + canonical_checkpoint_bytes(envelope)
    ).hexdigest()


def verify_checkpoint(
    envelope: Mapping[str, Any],
    trusted_fingerprint: str,
    expected_guard_id: str,
    last_seen_checkpoint: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Verify signature, identity, and trusted checkpoint progression."""

    if not isinstance(envelope, Mapping):
        raise CheckpointError("Envelope must be a mapping")

    if set(envelope) != REQUIRED_FIELDS:
        raise CheckpointError("Unexpected checkpoint fields")

    if type(envelope["schema_version"]) is not int:
        raise CheckpointError("Invalid schema version type")

    if envelope["schema_version"] != SCHEMA_VERSION:
        raise CheckpointError("Unsupported schema version")

    if not isinstance(envelope["algorithm"], str):
        raise CheckpointError("Invalid algorithm type")

    if envelope["algorithm"] != ALGORITHM:
        raise CheckpointError("Unsupported signature algorithm")

    if not isinstance(expected_guard_id, str) or not expected_guard_id:
        raise CheckpointError("Expected guard identity is required")

    if not isinstance(envelope["guard_id"], str):
        raise CheckpointError("Invalid guard identity")

    if envelope["guard_id"] != expected_guard_id:
        raise CheckpointTrustError("Guard identity mismatch")

    sequence = envelope["sequence"]
    if type(sequence) is not int or sequence < 0:
        raise CheckpointError("Invalid checkpoint sequence")

    event_hash = envelope["event_hash"]
    if not isinstance(event_hash, str) or not HASH_PATTERN.fullmatch(event_hash):
        raise CheckpointError("Invalid event hash")

    previous = envelope["previous_checkpoint_hash"]
    if previous is not None and (
        not isinstance(previous, str)
        or not HASH_PATTERN.fullmatch(previous)
    ):
        raise CheckpointError("Invalid previous checkpoint hash")

    if (
        not isinstance(trusted_fingerprint, str)
        or not HASH_PATTERN.fullmatch(trusted_fingerprint.lower())
    ):
        raise CheckpointTrustError("Invalid trusted fingerprint")

    if not isinstance(envelope["public_key"], str):
        raise CheckpointError("Public key must be Base64 text")

    try:
        public_key_bytes = base64.b64decode(
            envelope["public_key"], validate=True
        )
    except (ValueError, base64.binascii.Error) as exc:
        raise CheckpointError("Invalid public-key encoding") from exc

    if len(public_key_bytes) != 32:
        raise CheckpointError("Invalid Ed25519 public key length")

    actual_fingerprint = hashlib.sha256(public_key_bytes).hexdigest()

    if not isinstance(envelope["key_id"], str):
        raise CheckpointError("Invalid key identifier")

    if actual_fingerprint != envelope["key_id"]:
        raise CheckpointTrustError("Key identifier mismatch")

    if actual_fingerprint != trusted_fingerprint.lower():
        raise CheckpointTrustError("Untrusted checkpoint signing key")

    if not isinstance(envelope["signature"], str):
        raise CheckpointError("Signature must be Base64 text")

    try:
        signature = base64.b64decode(
            envelope["signature"], validate=True
        )
    except (ValueError, base64.binascii.Error) as exc:
        raise CheckpointError("Invalid signature encoding") from exc

    if len(signature) != 64:
        raise CheckpointError("Invalid Ed25519 signature length")

    signed_fields = {
        key: value
        for key, value in envelope.items()
        if key != "signature"
    }

    try:
        Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(
            signature,
            DOMAIN + canonical_checkpoint_bytes(signed_fields),
        )
    except InvalidSignature as exc:
        raise CheckpointTrustError(
            "Checkpoint signature verification failed"
        ) from exc

    if last_seen_checkpoint is None:
        if previous is not None:
            raise CheckpointRollbackError(
                "Initial checkpoint must not reference a predecessor"
            )
    else:
        if not isinstance(last_seen_checkpoint, Mapping):
            raise CheckpointError("Invalid trusted checkpoint anchor")

        old_sequence = last_seen_checkpoint.get("sequence")
        old_digest = last_seen_checkpoint.get("checkpoint_hash")

        if type(old_sequence) is not int or old_sequence < 0:
            raise CheckpointError("Invalid trusted sequence")

        if (
            not isinstance(old_digest, str)
            or not HASH_PATTERN.fullmatch(old_digest)
        ):
            raise CheckpointError("Invalid trusted checkpoint digest")

        if sequence <= old_sequence:
            raise CheckpointRollbackError(
                "Stale or repeated checkpoint"
            )

        if previous != old_digest:
            raise CheckpointRollbackError(
                "Checkpoint does not extend the trusted checkpoint"
            )

    result = dict(envelope)
    result["checkpoint_hash"] = checkpoint_digest(envelope)
    return result
