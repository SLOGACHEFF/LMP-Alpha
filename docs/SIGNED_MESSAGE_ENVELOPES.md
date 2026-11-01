# LMP Signed Message Envelopes (alpha)

## Purpose

A federation relay must not replace the original author with the immediate TLS peer. `SignedMessageEnvelope` is a draft origin-authenticated container intended to preserve the original author's identity across future relays. It is not yet integrated into the node wire handler and does not itself authorize a relay.

## Signed fields

The Ed25519 signature covers a domain-separated canonical JSON object containing:

- envelope version;
- origin Principal ID and signed identity document;
- stable message ID and recipient;
- creation and expiry timestamps;
- body encoding and body data.

The body supports UTF-8 JSON values (`str`, `dict`, `list`) or opaque bytes. A body change, recipient change, expiry change, or origin-document change invalidates the signature.

## Validation rules

- The origin identity document must verify and its Principal ID must match the envelope.
- The active Ed25519 key in that document must verify the signature.
- The message ID is limited to 128 characters; recipient to 256 characters.
- Envelope lifetime is limited to seven days. Expired envelopes and timestamps more than five minutes in the future are rejected.
- Unknown fields and non-canonical envelope encoding are rejected.

## Security limits

An origin signature proves that the origin key signed the envelope; it does not prove that the message is truthful, benign, or authorized for a given recipient. Relays still require a separate allowlist/policy, rate limits, hop-count or loop prevention, and durable deduplication. This alpha uses canonical JSON for the envelope and does not yet freeze a wire-compatible schema. Do not treat it as production-ready E2EE; the body is not encrypted by this envelope.
