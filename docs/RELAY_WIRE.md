# Signed envelope relay wire path (alpha16)

This document describes the experimental `TYPE_SIGNED_ENVELOPE` path. It is not
an approved stable wire specification.

## Frame payload

The frame payload is a CBOR map with exactly two byte-string fields:

- `envelope`: canonical JSON bytes for `SignedMessageEnvelope`.
- `relay_trace`: canonical JSON bytes for `RelayTrace`.

The outer frame is bounded by the configured maximum frame size. The trace parser
rejects non-canonical encodings, unknown fields, and traces above the hard 16-hop
limit before cryptographic verification.

## Receiver rules

1. The connection must first complete TLS 1.3 and the LMP identity handshake.
2. The origin signature and expiry of the envelope are verified.
3. If the authenticated peer is the envelope origin, the trace must be empty.
4. Otherwise, `allowed_relays` must be explicitly configured and include the peer.
5. Every receipt must verify against the envelope hash and previous receipt hash;
   each receipt identity must be allowed, unique, and non-origin.
6. The last receipt must identify the authenticated peer.
7. The message is stored with the original origin Principal ID as sender. `STORED`
   means local durable acceptance only, not recipient delivery.

## Operational limitations

The caller still orchestrates forwarding and supplies policy. This increment does
not add automatic route discovery, a multi-hop scheduler, end-to-end encryption,
or TLS-exporter channel binding. Relay receipts attest to signed statements; they
are not independent proof that a downstream recipient received or read a message.
