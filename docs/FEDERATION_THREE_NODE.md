# Three-node federation integration — alpha19

## What is now wired

`NodeConfig` accepts two optional, paired settings:

- `federation_outbox`: an object exposing `enqueue(...)` (normally `FederationOutbox`).
- `federation_route_selector`: a synchronous callback that receives the envelope recipient and returns a next-hop Principal ID or `None`.

When a signed envelope is received and authenticated, the node first stores the logical message in its local message store. If a next hop is selected, it then enqueues the exact `envelope` bytes and received `relay_trace` bytes. Only after the enqueue succeeds does the node send its `STORED` acknowledgement. A retry is idempotent across the message store and outbox, keyed by origin Principal ID plus message ID.

The forwarding worker can then claim the durable outbox item, validate the route and original signature, append and persist its own signed relay receipt, and transmit it over TLS 1.3 to the next node. The destination independently validates the relay trace and stores the message under the original author's Principal ID.

## Verification

`tests/test_federation_three_node.py` runs actual local TLS servers for B and C. A submits a signed envelope to B; B enqueues the immutable bytes; B's storage handles are closed and reopened; the worker forwards the message to C; and assertions verify that the destination stores the same message ID and original author. This is an integration test using local test certificates, not a production deployment test.

## Limitations

- Route selection is configured by the application; no automatic discovery or graph route calculation exists.
- The outbox and inbox use separate SQLite databases/transactions. The design handles retry after a partial failure through idempotent keys, but it is not a single cross-store atomic transaction.
- A `STORED` response from B means B has accepted the message and any configured forwarding enqueue has completed. It does not mean C has received it.
- This does not implement end-to-end encryption, TLS exporter binding, rate limiting, or a production operations model.
- Install the declared `cbor2` dependency to run tests against the real CBOR implementation. A local compatibility shim is not proof of interoperability.
