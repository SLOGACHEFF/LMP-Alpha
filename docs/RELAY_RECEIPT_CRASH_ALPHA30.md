# LMP Core alpha30 — relay-receipt crash recovery

## Goal
Prove the worker can recover after an abrupt process death at the critical boundary
between durable relay-trace persistence and recording the network attempt.

## Test sequence
1. A real `FederationOutboxWorker` claims an item.
2. `_send_one` appends and persists the relay receipt.
3. Fault injection hard-exits the child OS process when `record_attempt` is reached.
4. The parent opens the same SQLite database and verifies the receipt is durable,
   the item remains `PENDING`, and no network attempt was recorded.
5. A new worker reclaims the item after lease expiry, verifies and reuses the saved
   trace, sends the unchanged origin-signed envelope, and receives a matching `STORED` ACK.
6. The persisted and transmitted traces are byte-for-byte identical and contain
   exactly one receipt for this relay.

## Limits
This is a deterministic subprocess fault-injection test; it is not a power-loss test
or a live multi-host network test. It exercises the real worker path up to the
injected crash boundary. Runtime implementation and wire protocol are unchanged.
