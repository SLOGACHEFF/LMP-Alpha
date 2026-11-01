# LMP Core alpha23 — Stability Matrix

This matrix distinguishes implementation present in the repository from evidence still required for a stable product.

| Area | Current baseline | Evidence in alpha23 | Remaining gate | Priority |
|---|---|---|---|---|
| Packaging/install | `pyproject.toml` declares `cbor2` and `cryptography` | Wheel builds with `--no-deps`; official `cbor2` missing in audit environment | Clean install and full test run with declared dependencies | P1 |
| Wire framing | Fixed 20-byte header, maximum frame size, invalid flags/type checks | Unit tests in `tests/test_framing.py` | Fuzzing and bounded reads for authenticated sessions | P2 |
| Identity/authentication | Signed identity docs and challenge proof; TLS 1.3 enforced by node | Identity and node security tests | Independent review and deployment admission profile | P1 before public deployment |
| Signed envelope | Origin signature, bounded TTL, stable message ID | `tests/test_signed_envelope.py` | Real-CBOR interoperability vectors and adversarial fuzzing | P1 |
| Relay trace | Signed, ordered receipts; allow-list, loop and hop checks | `tests/test_relay.py` | More cross-node adversarial integration coverage | P1 |
| Durable inbox | SQLite persistence, deduplication, conflict detection, lease claims | `tests/test_message_store.py` | Disk failure, multi-process, and expiry-boundary tests | P2 |
| Federation outbox | SQLite WAL/FULL, idempotent enqueue, lease token fencing | `tests/test_federation_outbox.py` | Multi-process crash/recovery and storage fault injection | P1 |
| Delivery semantics | At-least-once send; correlated `STORED` ACK; dedup on receiver | `tests/test_federation_three_node.py` | Real network failure matrix and restart tests under process kill | P1 |
| Route failover | Policy callback, signed candidate route verification, route history | `tests/test_federation_worker.py` | Reject local Principal ID; add failure-path matrix | P1 |
| Expiry | Outbox `EXPIRED` terminal state | `tests/test_federation_worker.py` | Preserve absolute signed expiry in inbox; fractional boundary tests | P2 |
| Availability | TLS handshake timeouts, frame-size bounds | Node implementation and threat model | Idle/per-frame deadlines, connection admission, rate limiting | P2 / P1 if public |
| Operations | Statuses include pending/sent/failed/expired | Source and docs | Metrics, alerting, retention/cleanup, backpressure and runbook | P2 |

## Quality levels

- **L0 — Builds:** source compiles and package metadata builds.
- **L1 — Reproducible tests:** clean dependency install, full test suite, no test-only shim.
- **L2 — Fault-tolerant behavior:** restart, lease expiry, lost ACK, duplicate send, malformed input, and storage/network fault tests.
- **L3 — Stable deployment candidate:** security review, resource limits, operational telemetry/runbook, compatibility policy, and real interoperability tests.

Audit status: **L0 partially demonstrated; L1 not yet demonstrated; L2 partial; L3 not met.**


## Alpha24 remediation status

| Finding | Status in alpha24 | Regression evidence | Remaining work |
|---|---|---|---|
| STAB-001 — official dependency/reproducibility | Open | Full test suite runs with temporary shim only | Install real `cbor2`, run clean CI and canonical vectors |
| STAB-002 — local identity as failover hop | Fixed in code | `test_worker_refuses_local_identity_as_alternate_next_hop` | Keep route-selection property tests |
| STAB-003 — rounded inbox expiry | Fixed in code | absolute-expiry store tests; signed path now uses `expires_at` | Add receive-boundary tests against real wire integration |
| STAB-004 — authenticated frame read has no deadline | Fixed in code | authenticated idle TLS integration test | Stress-test partial frames and many concurrent clients |
| STAB-005 — deployment admission controls | Open/documented limitation | Existing allowlist tests | Define and test production deployment profile and admission/rate policy |
