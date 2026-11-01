## 0.1.0a31
- Strengthened the real TLS A -> B -> C integration test for duplicate ingress and lost STORED ACK recovery.
- Verifies the exact origin-signed envelope bytes and relay-trace bytes remain identical across retries and only one logical destination message is stored.
- No runtime implementation or wire-protocol changes.

## 0.1.0a30
- Added a subprocess fault-injection test that hard-exits the real federation worker immediately after durable relay-trace persistence and before network-attempt recording.
- Verified restart reuses the persisted relay receipt without duplicating it and only sends after recovery.
- No runtime implementation or wire-protocol changes.

## 0.1.0a29
- Added a real subprocess-termination regression test for a durable federation-outbox claim.
- Verified lease expiry recovery, exact envelope-byte preservation, lease-token rotation, and stale-worker completion fencing after abrupt process death.
- No runtime implementation or wire-protocol changes.
- Full-suite validation remains dependent on installing the declared `cbor2` dependency.

## 0.1.0-alpha24

- Stabilization patch: reject the local node identity as a federation failover next hop, preventing self-routing and false `SENT` outcomes.
- Preserve signed-envelope absolute expiry in the inbox instead of reconstructing it from a rounded remaining TTL; legacy `ttl_seconds` storage callers remain compatible.
- Add configurable authenticated frame-read/idle timeout (`NodeConfig.frame_read_timeout`, default 30 seconds; allowed range 0.1–300 seconds).
- Add regression tests for self-route rejection, absolute expiry persistence, invalid expiry inputs, timeout configuration, and authenticated idle-connection closure.
- Validation: see `docs/STABILITY_AUDIT_ALPHA23.md` for the stabilization follow-up and current environment limitations; full official-CBOR validation remains required where `cbor2` can be installed.

## 0.1.0-alpha23

- Added a policy-injected route failover hook for messages whose current next-hop route or identity document is missing.
- Alternate next hops must have a valid, non-expired signed route record and configured identity document; origin and already-visited relay identities are rejected to prevent loops.
- Persisted next-hop changes under the current lease fencing token.
- Added durable route-attempt history so a selector cannot oscillate between previously tried hops; legacy outbox rows seed their current hop during migration.
- Added tests for failover, persisted route selection, stale-token rejection, and route-history loop prevention.
- Validation in the current environment: 98 tests pass with the temporary CBOR shim; 76 selected tests pass without the shim. The full suite still needs the official `cbor2` dependency installed for a clean run.
- Failover is still configuration-driven and currently handles missing route metadata, not automatic switching after network connection failures. Official `cbor2` interoperability remains to be tested in an environment with the dependency installed.

## 0.1.0-alpha22

- Treat signed envelope expiry as a terminal `EXPIRED` outbox state instead of repeatedly retrying an envelope that can no longer be delivered.
- Add lease-fenced expiration transitions and deterministic worker clock injection for expiry tests.
- Add regression coverage proving expired messages are not sent or retried.

## 0.1.0-alpha21

- Extended the three-node TLS integration test to simulate a lost acknowledgement after the destination has already durably stored a message.
- Verified the relay retries using the persisted origin envelope and relay receipt, the destination deduplicates the retry, and the outbox eventually records `SENT` after a correlated `STORED` acknowledgement.
- Attempted to install the declared official `cbor2` dependency for a clean test run; package retrieval was blocked by unavailable network/DNS in this environment. Tests still require the previously documented temporary shim here, so official-library interoperability remains unverified.

## 0.1.0-alpha20

- Added per-claim random lease fencing tokens to the federation outbox.
- Outbox updates (trace persistence, retry, failure, acknowledgement) now require the current token, preventing a stale worker from mutating a row after lease reclamation—even when the same worker ID is reused.
- Fixed claim result selection to return only rows claimed by that exact transaction rather than querying by worker ID and lease timestamp.
- Added regression tests for stale tokens and repeated claims by the same worker.
- Existing alpha17-alpha19 SQLite databases are migrated by adding the nullable token column at startup.

## 0.1.0-alpha19

- Wired optional recipient-based federation forwarding into the signed-envelope receive path. When configured with a federation outbox and route selector, a node persists the original envelope bytes and incoming relay trace before acknowledging `STORED`.
- Added a three-node TLS integration test covering A → B → C, persistence across a relay process restart, origin-signature preservation, and durable acceptance at the destination.
- This remains opt-in routing: deployments must configure the outbox and route selector. Automatic discovery and route computation are not included.

# Changelog

## 0.1.0-alpha18
- Added `FederationOutboxWorker`, connecting durable outbox leases to signed route records and `send_signed_envelope()`.
- Persisted the relay receipt before network I/O so retries reuse the same local receipt instead of appending duplicate hops.
- Added a prepared-trace send mode that verifies a previously persisted trace and checks that it ends at the authenticated local relay.
- Added a lease-scoped terminal failure transition and tests for route-aware sending, byte-for-byte origin envelope preservation, receipt persistence, acknowledgement, and missing-route retries.
- This is a configured single-next-hop worker; route discovery and automatic multi-hop route computation remain unfinished.

## 0.1.0-alpha17
- Added a dedicated SQLite federation outbox that preserves exact origin-signed envelope bytes and relay-trace bytes across process restarts.
- Added idempotent enqueue keyed by origin Principal ID + message ID, conflict detection, worker leases, retry scheduling, trace updates, and worker-scoped acknowledgements.
- Added tests for restart recovery, byte-for-byte preservation, duplicate insertion, invalid encoding, leases, retries, and acknowledgement ownership.
- The outbox is a storage primitive; automatic route selection and a network delivery worker are not yet connected.


## 0.1.0-alpha16
- Added `TYPE_SIGNED_ENVELOPE` and a network receive path for immutable origin-signed messages.
- Added `send_signed_envelope()` with TLS 1.3 and LMP identity checks, request/ack correlation, and optional signed relay receipt append.
- Enforced explicit receiving-side relay allow-lists, receipt-chain validation, last-hop/peer binding, and durable storage under the origin Principal ID.
- Added canonical bounded serialization for relay traces and direct-origin, authorized-relay, and untrusted-relay integration tests.
- Updated README to reflect current wiring and explicitly list remaining security gaps.

## 0.1.0-alpha15
- Added signed relay receipts chained to the immutable origin-signed envelope hash.
- Added relay allow-list enforcement, loop detection, bounded hop counts, timestamp checks, and receipt-chain validation.
- Added tests for valid multi-hop traces, untrusted relays, loops, hop limits, tampering, reordering, and envelope mismatch.
- Restored project README and documented relay policy limitations.

## 0.1.0-alpha14
- Added origin-signed message envelopes preserving authorship across future federation relays.
- Bound message ID, recipient, body, origin identity document, creation time, and expiry into an Ed25519 signature.
- Added strict canonical encoding, recipient/expiry checks, and envelope tampering tests.
- Documented that origin signatures do not by themselves authorize relays or guarantee delivery.

## 0.1.0-alpha13
- Added `FederationSender`, connecting validated route records to the durable delivery worker.
- Generalized `send_message` to accept explicit recipient and stable message ID, and to validate the remote `STORED` acknowledgement.
- Added tests for route resolution, acknowledgement correlation, missing routes, and rejection of third-party-origin forwarding.
- Documented federation sender scope and current relay limitation.

## 0.1.0-alpha12
- Added signed, expiring node route advertisements and in-memory verified route cache.

## 0.1.0-alpha11
- Added delivery worker with lease-based queue claims, retry scheduling, exponential backoff, and terminal failure handling.

## 0.1.0-alpha10
- Added durable message queue primitives with leases, expiry, retries, and SQLite schema migration.

## 0.1.0-alpha9
- Added SQLite-backed persistent message storage and deduplication.

## 0.1.0-alpha8
- Tightened transport settings and handshake response validation; added initial two-node integration test scaffolding.

## 0.1.0-alpha7
- Integrated identity checks into the network handshake path and added encrypted identity-key storage.

## 0.1.0-alpha6
- Added handshake transcript binding primitives.

## 0.1.0-alpha5
- Added one-time identity challenge tracking.

## 0.1.0-alpha4
- Added identity challenge-response proof primitives.

## 0.1.0-alpha3
- Added initial identity document and Principal ID implementation.


## Stabilization infrastructure (alpha24, no wire/API change)

- Added CI on Python 3.12 and 3.13 that installs the declared runtime/test dependencies, reports actual dependency versions, runs the full suite without test shims, compiles source/tests, and builds a wheel.
- Added an exact deterministic-CBOR byte-vector test to detect canonical map-ordering regressions.
- This environment cannot reach the package index, so the new clean-dependency CI job has been defined but not executed here. The local shim run is diagnostic only.

## 0.1.0a25 — federation fault-recovery hardening

- Separate durable claim count (`claims`) from actual network-send attempts (`attempts`) in the federation outbox.
- Add a fenced `record_attempt` operation immediately before network I/O; a worker crash after claiming but before sending no longer consumes the configured send-attempt budget.
- Add migration for existing outbox databases to introduce the `claims` counter without dropping queued messages.
- Add fault-injection coverage for process restart, lease expiry/reclaim, stale-token fencing, and transaction rollback when route-history persistence fails.
- Keep the existing TLS three-node lost-ACK integration test as the end-to-end duplicate-delivery recovery check.


## 0.1.0a26 — official CBOR dependency verification

- Raise the minimum supported `cbor2` version to 5.7.1 while retaining the tested 5.x compatibility range.
- Strengthen CI to assert that `cbor2` is imported from installed `site-packages`, not a repository shim.
- Add an isolated wheel-install test that runs the suite outside the source tree against the built distribution.
- Make `tests/conftest.py` support explicit installed-wheel testing via `LMP_TEST_INSTALLED_WHEEL=1`.
- Local full-suite validation remains blocked because this environment cannot resolve the package index; CI is configured to perform the real-dependency run.


## 0.1.0-alpha27 — Federation storage fault injection

- Added cross-process SQLite claim contention test using independent worker processes.
- Added injected SQLite failure during acknowledgement; verifies `SENT` is not persisted on failure and a subsequent acknowledgement can complete.
- No wire protocol or runtime behavior changes in this iteration.
- Full suite remains pending verification with the official `cbor2` dependency; shim-based results are not release evidence for CBOR interoperability.


## 0.1.0-alpha28 — Federation crash-window recovery tests

- Added a crash-boundary regression test for failure after the relay receipt is durably persisted but before the network send begins; after reopening SQLite, the worker must reuse the same single receipt.
- Added a lost-ACK scenario where the receiver durably stores a message but the sender times out; retry must preserve the signed envelope and relay trace and complete idempotently.
- No runtime protocol behavior changed; this iteration adds tests and documentation only.
- Official `cbor2` is still absent in this environment, so complete-suite results must not be represented as official CBOR interoperability evidence.
