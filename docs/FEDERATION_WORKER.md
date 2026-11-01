# Federation Outbox Worker — alpha draft

`FederationOutboxWorker` connects `FederationOutbox` to the signed-envelope network send API for a configured next hop.

## Processing sequence

1. Claim a pending outbox item under a worker lease.
2. Parse and verify the immutable origin-signed envelope and cross-check its origin/message IDs against the queue key.
3. Resolve the configured next-hop Principal ID in `RouteCache` and verify the signed route record against the configured identity document.
4. For a relay, verify the existing relay chain and append the local signed receipt. Persist the updated trace while the lease is held **before** network I/O.
5. Send the original envelope bytes plus the persisted trace using `send_signed_envelope()`.
6. Mark the outbox item `SENT` only when the next hop returns a matching `STORED` acknowledgement.
7. On transient errors or a missing route, release the lease with a retry delay. After the configured attempt limit, mark the item `FAILED`.

## Semantics and limitations

- The original origin-signed envelope is never reconstructed or re-signed by the relay.
- A relay receipt is persisted before network I/O, so a retry to the same or a new next hop does not append a duplicate receipt for the same relay.
- `STORED` means the next hop durably accepted the envelope; it does not mean the final recipient received or read it.
- Delivery remains at-least-once across network failures. Receiver-side deduplication is required.
- The worker uses a configured `next_hop` per outbox item. It does not discover routes, calculate shortest paths, or automatically enqueue downstream forwarding at each receiving node.
- A crash after the remote node stores a message but before the local acknowledgement is persisted may cause a resend. This is expected and must be handled through stable IDs and deduplication.
- TLS exporter channel binding, end-to-end encryption, and production hardening remain out of scope.

## Example construction

Construct the worker with a `FederationOutbox`, the local `IdentityKeyPair`, a CA bundle, a verified `RouteCache`, the identity documents for configured next hops, and an explicit `allowed_relays` set. Call `await worker.run_once()` repeatedly from an application-managed scheduler. Do not expose the alpha implementation to untrusted networks.
