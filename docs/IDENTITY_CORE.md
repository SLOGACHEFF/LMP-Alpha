# LMP Identity Core — alpha profile

**Status:** Draft / experimental. Not a stable wire standard.

## Scope

This document describes the initial local identity primitive in `lmp_core.security.identity`. It does not yet authenticate a live network peer, authorize a device, implement key rotation, or integrate the identity document into the node handshake.

## Key model

- Root identity key: Ed25519; anchors the genesis identity.
- Active signing key: Ed25519; published in the genesis document, and used by the challenge-response helper and the live network handshake.
- Principal ID: `SHA-256("LMP:PRINCIPAL:V1\\0" || root_public_key_raw)`, where the root public key is the 32-byte raw Ed25519 encoding.
- Text Principal ID: `lmp:p:` followed by lowercase unpadded Base32 of the 32-byte Principal ID.

The Principal ID is derived from the immutable genesis root public key, not from the current document. Future key rotation must preserve this ID and requires a separately specified authorization chain.

## Genesis identity document

The current document includes version, principal ID, revision, root public key, active signing public key, creation time, previous-document hash, signature algorithm, and signature. The genesis revision is `1` and its previous-document hash is null.

For this alpha, document bytes use deterministic JSON: UTF-8, sorted keys, compact separators, non-ASCII characters preserved, and non-finite numbers rejected. The root key signs the canonical unsigned document prefixed by `LMP:IDENTITY-DOCUMENT:V1\\0`.

This JSON profile is temporary. A future interoperable release must freeze a single canonical encoding and provide test vectors before identity documents are considered stable.

## Verification requirements

A verifier:

1. Rejects missing or unknown fields.
2. Requires supported version and revision `1`.
3. Checks key and signature lengths.
4. Recomputes the Principal ID from the root public key.
5. Verifies the root signature over the canonical unsigned document and domain separator.
6. Rejects non-canonical serialized bytes.
7. Fails closed on any verification error.

## Proof of possession (alpha4)

`IdentityKeyPair.sign_challenge()` signs a domain-separated payload containing the digest of the canonical identity document, a 32-byte challenge, and a length-delimited caller-supplied session binding. `verify_peer_proof()` verifies the identity document first, then checks the Ed25519 signature against the active signing key. The helper rejects malformed challenge/binding sizes and mismatched local key material.

The `IdentityChallenge` helper generates an unpredictable 32-byte challenge using the system cryptographic random source and consumes it on the first verification attempt, including a failed attempt. This one-shot state object is a standalone primitive and is not directly used by `node.py`; the live alpha handshake currently uses fresh client/server nonces and a transcript binding instead. A future implementation should unify these paths and expire pending handshakes. The transcript binding does **not** calculate TLS exporter/channel-binding data, and callers must not describe the proof as TLS-channel-bound unless they actually provide an independently authenticated binding.

A successful proof establishes possession of the active signing key for the supplied challenge/context. It does not itself authorize messaging or establish end-to-end encryption.

## Known limitations

- No identity-document revision chain or key rotation.
- No recovery mechanism.
- No device registration/delegation.
- Challenge-response helper exists, but no live proof-of-possession challenge in the network handshake.
- No identity discovery or revocation integration.
- The current primitive must not be treated as production-ready authentication.

## Handshake transcript binding (alpha6)

`HandshakeTranscript` derives a fixed-size LMP context binding from the client
nonce, server nonce, and both identity-document hashes. Both peers must use the
same client/server ordering and exact documents. The helper verifies both
identity documents before producing the binding. This gives challenge proofs a
consistent connection-specific context and prevents transplanting a proof to a
transcript with changed nonces or identities.

This is **not** a TLS exporter/channel binding. The helper is not yet wired into
`node.py`, and the node still does not require identity authentication before
accepting messages. Do not treat this alpha as production-ready.
