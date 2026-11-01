# LMP Core architecture (0.1.0-alpha2)

## Status

This is an experimental prototype, not a stable standard and not suitable for public Internet deployment.

## Module boundaries

- `protocol`: framing, CBOR codec, provisional frame codes.
- `transport`: byte transport interfaces; the current listener/client use asyncio TCP + TLS 1.3.
- `security`: identity and authorization contracts. The alpha has no full LMP Identity Document implementation.
- `messaging`: common message and delivery-state models.
- `network`: future discovery, routing, and relay adapters.
- `storage`: future durable message/object stores.
- `api.py`: shared Python types and contracts between modules.

## Trust boundaries

TLS protects a transport connection according to certificate validation policy. It does not by itself establish a permanent LMP Principal ID or authorize a claimed sender. The current demo accepts a claimed sender string and therefore must only be used in a controlled local test environment. The next security milestone is to bind the LMP identity verification and fail-closed authorization interfaces into the handshake and message path.

## First alpha scope

Implemented: bounded frame parsing, canonical CBOR encoding, TLS 1.3 listener/client, minimal version negotiation, basic message submission, in-memory duplicate suppression.

Not implemented: permanent identity documents, LMP signature verification, end-to-end encryption, durable delivery, federation routing, discovery, group messaging, file transfer, voice/video, production abuse protection.

## Compatibility rule

The Python interfaces in `api.py` are internal implementation contracts. They are not yet normative wire schemas. Changes to wire schemas must be documented separately and accompanied by test vectors.
