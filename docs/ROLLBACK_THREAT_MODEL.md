# JLMAI Sentinel — Registry Rollback Threat Model

**Document ID:** SENTINEL-001B
**Status:** Draft — Design Review
**Security principle:** Fail closed
**Scope:** Root registry state, signed status transitions, sequence checkpoints, and recovery

## 1. Objective

Prevent an attacker from restoring an older, previously valid root registry state and causing Sentinel to accept obsolete authority.

A valid digital signature proves that a signing key authorized particular data. It does not prove that the data is the newest authorized state.

Sentinel must verify both cryptographic authenticity and freshness against an independently protected checkpoint.

## 2. Assets to protect

1. Founder root public-key identity and trusted fingerprint.
2. Root authorization status, including revocation.
3. Highest accepted registry sequence.
4. Signed policy versions and policy integrity.
5. Checkpoint authenticity and history.
6. Recovery and key-rotation authority.
7. Audit evidence recording state transitions and verification decisions.

Private root-key material must remain outside the ordinary agent runtime.

## 3. Attacker capabilities

An attacker may:
- Read, modify, replace, or delete local registry files.
- Restore an older registry copy.
- Restore an older local checkpoint.
- Submit malformed or duplicated JSON fields.
- Replay previously valid signed states.
- Make the checkpoint source unavailable.
- Exploit compromised agents or execution adapters.
- Obtain write access to ordinary application storage.

Filesystem permissions alone are not assumed to prevent a privileged attacker from restoring local files.

## 4. Security requirements

### R-01 — Signature authenticity

Every accepted registry state must have a valid Ed25519 signature under the independently pinned root identity.

### R-02 — Strict sequence progression

The registry sequence must be strictly greater than the last independently accepted sequence.

### R-03 — Independent checkpoint

The checkpoint must not rely exclusively on storage that can be restored together with the registry.

### R-04 — Fail-closed verification

Missing, invalid, stale, or unavailable checkpoint information must deny sensitive operations.

### R-05 — Authenticated status transitions

ACTIVE and REVOKED transitions must be authenticated. A file edit alone must never reactivate a revoked identity.

### R-06 — Replay prevention

Previously accepted states must not be accepted again as current states.

### R-07 — Recovery separation

Recovery authority must be separate from ordinary agent authority. Root-key compromise must not be treated as safely recoverable by signing a new ACTIVE state with the compromised key.

### R-08 — Evidence preservation

State transitions, checkpoint advancement, rejected rollback attempts, and recovery events should be recorded in tamper-evident evidence.

## 5. Checkpoint trust model

The checkpoint records at minimum:
- Checkpoint schema version.
- Root identity fingerprint.
- Highest accepted registry sequence.
- Checkpoint generation or version.
- Authentication evidence.
- Creation or acceptance metadata.

The checkpoint must have an independent trust basis.

| Approach | Assessment |
|---|---|
| Another file on the same device | Not independently rollback-resistant |
| Offline separately controlled checkpoint | Suitable for an initial manual prototype |
| External trusted witness | Potentially stronger independent history |
| Hardware-backed monotonic counter | Desirable if verified hardware support exists |

For the initial prototype, use a manually controlled offline checkpoint. Do not represent it as automatic hardware-backed rollback protection.

## 6. Checkpoint advancement

Checkpoint advancement must:
1. Verify the registry signature.
2. Verify the pinned root identity.
3. Validate the registry schema and status.
4. Confirm the new sequence exceeds the previous checkpoint.
5. Require a separately authenticated checkpoint-update procedure.
6. Preserve evidence of the previous checkpoint and new state.

An agent must not advance the checkpoint simply by requesting an operation.

## 7. Revocation and compromise

A signed REVOKED state is useful only while its signing authority remains trustworthy.

If the root signing key is compromised, an attacker may be able to sign a later ACTIVE state. Therefore:
- Revocation must be anchored in a separately trusted recovery authority or governance procedure.
- Recovery must establish a new trust identity or explicitly authorized replacement.
- The old identity must remain recorded as compromised or revoked.
- Recovery must not silently erase previous evidence.

The exact recovery authority and custody procedure remain unresolved design decisions.

## 8. Failure behavior

| Condition | Required behavior |
|---|---|
| Invalid signature | Deny |
| Incorrect pinned fingerprint | Deny |
| Sequence equal to checkpoint | Deny |
| Sequence below checkpoint | Deny |
| Checkpoint unavailable | Deny sensitive operations |
| Invalid or unknown status | Deny |
| Revoked root | Deny |
| Malformed checkpoint | Deny |
| Recovery authority unavailable | Deny sensitive operations |

Read-only diagnostic access may be considered separately, but it must not imply authorization to execute sensitive actions.

## 9. Explicit limitations

The current `verify_registry_state()` implementation verifies signed state and compares its sequence with a caller-supplied value.

It does not:
- Persist the highest accepted sequence.
- Guarantee that the supplied checkpoint is independently protected.
- Provide hardware-backed monotonic storage.
- Define a complete root-key compromise recovery process.
- Guarantee tamper-proof audit storage.

These capabilities must not be claimed until separately implemented and tested.

## 10. Acceptance criteria

The design is ready for checkpoint implementation only after:
- The checkpoint trust source is selected.
- Its authentication mechanism is defined.
- Its rollback limitations are documented.
- Checkpoint update authority is defined.
- Root-key revocation and recovery procedures are reviewed.
- Fail-closed behavior is specified and testable.
- Adversarial tests cover registry and checkpoint rollback together.

## 11. Current decision

**Selected prototype direction:** Manually controlled offline checkpoint, with an interface designed for a future independent witness or hardware-backed implementation.

**Not authorized at this stage:** Founder root-key generation, production enrollment, deployment, or claims of hardware-backed rollback protection.

---

**JLMAI Sentinel — SENTINEL-001B**
**Document status:** Draft for founder review
