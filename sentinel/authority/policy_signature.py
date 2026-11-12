"""Ed25519 verification for JLMAI Sentinel signed policies.

This module verifies signatures. It does not generate or store private keys.
"""

import base64
import json
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


SIGNATURE_DOMAIN = b"JLMAI-SENTINEL-POLICY-SIGNATURE-V1\x00"


def canonical_policy_bytes(policy: Mapping[str, Any]) -> bytes:
    """Serialize a policy deterministically before signature verification."""
    if not isinstance(policy, Mapping):
        raise TypeError("Policy must be a mapping")

    try:
        serialized = json.dumps(
            dict(policy),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        return serialized.encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("Policy cannot be canonically serialized") from exc


def verify_policy_signature(
    public_key_bytes: bytes,
    policy: Mapping[str, Any],
    signature_b64: str,
) -> bool:
    """Verify an Ed25519 signature over a domain-separated policy."""
    if not isinstance(public_key_bytes, bytes) or len(public_key_bytes) != 32:
        raise ValueError("Ed25519 public key must contain exactly 32 bytes")

    if not isinstance(signature_b64, str):
        raise ValueError("Signature must be a Base64 string")

    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError("Signature is not valid Base64") from exc

    if len(signature) != 64:
        raise ValueError("Ed25519 signature must contain exactly 64 bytes")

    public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)

    message = SIGNATURE_DOMAIN + canonical_policy_bytes(policy)

    public_key.verify(signature, message)
    return True
