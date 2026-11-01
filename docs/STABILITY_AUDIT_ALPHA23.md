# LMP Core alpha23 — Stability Audit

**Audit date:** 2026-10-27  
**Scope:** source and tests in `lmp-core-v0.1` as provided; federation outbox/worker, signed-envelope acceptance, message expiry, framing, packaging and test reproducibility.  
**Disposition:** not ready to be treated as a stable production product. This is a code-and-test audit, not an independent cryptographic review or a production deployment test.

## Executive summary

The current revision has useful foundations: SQLite transactions and WAL/FULL for file-backed stores, stable message keys, lease fencing tokens, signed origin envelopes, relay receipt chains, bounded frame sizes, expiry states, and a three-node integration test. The test suite reports **98 passed only when the temporary CBOR compatibility shim at `/tmp/cbor2.py` is injected**. Without that shim, test collection stops with three `ModuleNotFoundError: cbor2` errors. The shim is not part of the repository and is not a substitute for the declared `cbor2` implementation or an interoperability test.

A targeted runtime probe confirmed a routing correctness defect: the route-failover worker accepts its own local Principal ID as an alternate next hop. The message can then be sent back to the same node and the outbox row marked `SENT`, without reaching the intended next hop. A second confirmed timing issue can extend the local inbox expiry beyond the signed envelope's `expires_at` by less than one second.

No production source files were changed as part of this audit. The findings below should be addressed in a controlled stabilization iteration, with regression tests first.

## Findings register

### STAB-001 — Test results are not reproducible with declared runtime dependencies

- **Priority:** P1 — release blocker for trustworthy validation.
- **Status:** Confirmed in the audit environment.
- **Evidence:** `pyproject.toml` declares `cbor2>=5.6,<6`; `src/lmp_core/codec.py:4` imports it at module load. `python -m pytest -q` fails collection in `tests/test_codec.py`, `tests/test_federation_three_node.py`, and `tests/test_node_security.py` because `cbor2` is absent.
- **Observed result:** no-shim suite exits 2 before all tests run. With `PYTHONPATH=/tmp` pointing at the temporary, non-project CBOR subset shim, the suite reports `98 passed in 1.06s`.
- **Impact:** the green shim run does not establish compatibility with the declared CBOR library, nor canonical-encoding interoperability. This audit environment has not verified a clean install with official `cbor2`.
- **Acceptance criteria:** in a clean environment, install `.[test]` from the project metadata; `python -m pytest -q` passes with the real `cbor2`; add a CI job that performs that install and run; include at least one known CBOR interoperability/canonical encoding vector. Record Python and dependency versions in CI output.

### STAB-002 — Route failover can select the local node as its own next hop

- **Priority:** P1 — message-forwarding correctness.
- **Status:** Confirmed by targeted runtime probe.
- **Evidence:** `src/lmp_core/federation/worker.py:145-169` rejects the failed hop, origin, and relays already in the trace, but does not reject `candidate == self.identity_keys.principal_id_text`. A valid route record for the local identity passes the subsequent checks. `tests/test_federation_worker.py:95-133` covers a different alternate but not this case.
- **Observed result:** a local probe configured `route_failover` to return the worker's own Principal ID. First pass persisted the local node as `next_hop`; second pass called the send function with `expected_server_principal` equal to the local node and marked the outbox item `SENT` after the mock returned `STORED`.
- **Impact:** a misconfigured selector or route cache can cause a message to be delivered back to the forwarding node and the queue item to be marked sent without reaching the intended next hop. In an integrated deployment this can suppress forwarding or create a self-routing loop.
- **Recommended correction:** reject the local Principal ID before persisting any alternate route. Add a regression test asserting the candidate is rejected, `next_hop` is unchanged, and no send is attempted to the local identity.
- **Acceptance criteria:** failover candidates equal to the origin, local node, failed hop, any prior relay, or any previously attempted next hop are rejected; all such cases are covered by tests.

### STAB-003 — Inbox expiry is recomputed from a rounded remaining TTL

- **Priority:** P2 — expiry semantics.
- **Status:** Confirmed by code inspection; the exact boundary needs a regression test.
- **Evidence:** `src/lmp_core/node.py:261-264` passes `envelope.expires_at - int(time.time())` as `ttl_seconds`; `src/lmp_core/storage/message_store.py:127-132` then sets `expires_at = time.time() + ttl_seconds` using a fractional wall-clock value.
- **Impact:** if the receive happens between integer-second boundaries, the local inbox's expiry can be later than the signed envelope expiry by less than one second. `pending_for()` and `claim_pending()` use the stored inbox expiry, so a message may remain eligible for local delivery briefly after the origin envelope's validity window ends.
- **Recommended correction:** persist the signed absolute expiry timestamp for signed envelopes (or calculate remaining TTL from a single precise timestamp without integer truncation). Do not change the legacy unsigned-message API without compatibility tests.
- **Acceptance criteria:** for receive times with fractional seconds, stored expiry never exceeds `envelope.expires_at`; boundary tests cover just-before, exact, and just-after expiry.

### STAB-004 — Authenticated connections have no idle/frame-read deadline

- **Priority:** P2 — availability hardening.
- **Status:** Confirmed as a code gap; exploitability depends on deployment exposure and admission policy.
- **Evidence:** the handshake reads use `asyncio.wait_for(..., timeout=10)` at `src/lmp_core/node.py:109-110` and `148`, but the authenticated main loop at `src/lmp_core/node.py:171-178` calls `read_frame()` without a deadline. `read_frame()` waits for the full header and payload at `src/lmp_core/node.py:71-77`. The threat model also lists connection admission/rate limiting as a gap (`docs/THREAT_MODEL.md`).
- **Impact:** a peer that completes authentication can hold a connection handler while sending no next frame or only a partial frame. With permissive/default admission settings and enough connections, this can consume server resources.
- **Recommended correction:** add configurable idle and per-frame read deadlines, close timed-out sessions, and define a connection admission/rate policy for deployments.
- **Acceptance criteria:** integration tests prove stalled headers and stalled payloads are closed within configured bounds; timeout cleanup does not leak tasks or writers; normal slow-but-valid traffic has documented limits.

### STAB-005 — Deployment security controls are still opt-in and incomplete

- **Priority:** P1 for public/untrusted deployment; P2 for isolated lab use.
- **Status:** Documented limitation, not newly discovered defect.
- **Evidence:** `NodeConfig.allowed_principals` defaults to `None` (`src/lmp_core/node.py:37`), and authorization is only applied when a set is configured (`src/lmp_core/node.py:161-164`). `README.md` and `docs/THREAT_MODEL.md` explicitly warn that this is not production-ready and that connection admission/rate limiting and other hardening remain incomplete.
- **Impact:** TLS and cryptographic identity prove who a peer is, but do not by themselves establish that the peer is authorized to use a deployment. Deployments must not assume the default config is a restrictive admission policy.
- **Acceptance criteria:** production-facing configuration requires an explicit admission policy or makes permissive mode unmistakable; documentation includes a secure deployment profile and tests verify fail-closed behavior when policy is required.

## Verification log

| Check | Result | Interpretation |
|---|---|---|
| `python -m pytest -q` (no shim) | **Failed during collection**, exit 2; missing `cbor2` in three test modules | Full suite not verified with declared dependency |
| `PYTHONPATH=/tmp python -m pytest -q` | **98 passed** | Diagnostic only; `/tmp/cbor2.py` is a temporary subset shim outside the project |
| `python -m compileall -q src tests` | Passed | Python syntax compilation only |
| `python -m pip wheel --no-deps --no-build-isolation .` | Passed; built `lmp_core-0.1.0a23-py3-none-any.whl` | Packaging metadata/build works in this environment; dependencies were not installed or tested |
| `unzip -t lmp-core-v0.1-alpha23.zip` | Passed | Existing alpha23 archive is structurally readable |
| `python -m pip check` | Reports unrelated environment conflict: `moviepy 2.2.1` requires `pillow<12`, installed `pillow 12.3.0` | Global environment is not dependency-clean; not attributed to LMP without further evidence |
| Targeted self-route failover probe | Reproduced local next-hop selection and `SENT` state | Confirms STAB-002 |

## Test coverage gaps before stability sign-off

The current tests are useful unit and selected integration tests, but the following scenarios should be added or demonstrated before a stable release:

1. Official `cbor2` in a clean environment, including canonical CBOR vectors and malformed/deeply nested input bounds.
2. Failover to self, origin, a prior relay, a previously attempted hop, a route whose identity does not match, and a route that expires between selection and send.
3. Inbox/outbox expiry boundaries using fractional timestamps.
4. Authenticated peers stalling at each frame boundary; connection-count and slow-client stress tests.
5. Multi-worker contention under real processes, stale lease after a long network operation, process kill between remote `STORED` and local ACK persistence, and recovery after restart.
6. SQLite disk-full/read-only/corrupt database behavior and migration rollback tests.
7. Network integration with real TLS contexts and verified routes, not only injected `send_func` paths.
8. Fuzz/property tests for frame headers, CBOR payloads, signed envelopes, identity documents, and relay traces; explicit message-size and nesting-depth policies.
9. A documented operational policy for retention of `SENT`, `FAILED`, and `EXPIRED` rows, metrics, alerting, and queue backpressure.

## Stabilization exit gates

Do not declare the protocol stable until all of the following are true:

- [ ] Clean install with official dependencies and reproducible full test run in CI.
- [ ] STAB-002 fixed with regression coverage; STAB-003 fixed or its exact boundary semantics explicitly justified and tested.
- [ ] STAB-004 has bounded connection/frame waits and stress-test evidence.
- [ ] Crash/retry/idempotency tests pass across process restart and separate workers.
- [ ] Security review verifies fail-closed deployment configuration, signed identity/route checks, and relay authorization boundaries.
- [ ] Wire compatibility and supported version policy are documented; interoperability tests use the real CBOR implementation.
- [ ] Observability, queue retention, resource limits, and failure recovery are documented and tested.

## Stabilization follow-up — alpha24

The next narrow patch was implemented and is versioned as `0.1.0a24`:

- **STAB-002:** failover now rejects the local node's own Principal ID before route-cache lookup or persistence. Regression test verifies the next hop remains unchanged and the send callback is never invoked.
- **STAB-003:** `SQLiteMessageStore.store()` now accepts a validated absolute `expires_at` parameter, mutually exclusive with `ttl_seconds`. The signed-envelope receive path passes the signed absolute expiry directly, avoiding rounded TTL reconstruction. Regression tests verify exact persistence and reject past/conflicting expiry arguments.
- **STAB-004:** `NodeConfig.frame_read_timeout` (default 30 seconds; range 0.1–300 seconds) now bounds authenticated frame reads, including idle and partial-frame reads. A TLS integration test authenticates a peer and verifies that the idle connection is closed.

The alpha24 tests were run with the temporary CBOR shim: **104 passed**. This is a regression signal, not official CBOR interoperability proof. The real `cbor2` dependency is still unavailable in this environment, so the clean-dependency full-suite gate remains open. Re-run the suite with official `cbor2` before any stable-release decision.

**Current conclusion:** alpha24 addresses these three confirmed code issues, but the project is not yet stable. STAB-001 remains open; operational admission/rate limiting, real-dependency interoperability, multi-process crash/retry behavior, and broader stress/security testing remain release gates.
