# LMP Relay Policy (alpha draft)

## Purpose

Origin-signed message envelopes protect authorship and contents. They do not
by themselves authorize a server to relay a message. This module adds a bounded
chain of per-hop signed receipts, while leaving the original envelope unchanged.

## Receipt chain

Each `RelayReceipt` binds the stable `message_id`, SHA-256 hash of the exact
canonical envelope bytes, hop index, relay Principal ID, signed identity
document, creation time, and hash of the previous receipt. A relay signs the
canonical fields with its active Ed25519 key under the domain
`LMP:RELAY-RECEIPT:V1\0`.

The first receipt points to a fixed all-zero genesis hash. Each subsequent
receipt points to the hash of the preceding complete receipt. Reordering,
removing, or modifying a receipt therefore invalidates the chain.

## Authorization and bounds

- Appending requires an explicit `allowed_relays` allow-list. Missing policy is
  a denial, not an implicit allow.
- Verification requires an explicit allow-list for all relays in the chain.
- The configured hop limit must be between 1 and 16; the recommended default is 8.
- A relay may appear only once in a trace, and the origin may not appear as a relay.
- Receipts must be in order, bind to the same envelope, and have timestamps within
  the configured age/future-skew policy.
- Every relay identity document and signature is verified independently.

## Limitations

This is an alpha policy primitive and is not yet integrated into the network frame
handler or `FederationSender`. A receipt proves that a key signed a forwarding
statement; it does not prove that the relay actually delivered the message or
that a destination stored it. Allow-lists are supplied by the caller and are not
federated automatically. Canonical JSON is temporary and may be replaced by a
frozen canonical CBOR profile before a stable protocol release.
