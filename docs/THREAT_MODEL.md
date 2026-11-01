# Initial threat model

## Assets

- identity and key material;
- message contents and metadata;
- integrity of frames and message state;
- node availability and storage capacity;
- authorization and routing decisions.

## Threats considered

Malformed or oversized frames, unauthenticated peers, forged sender labels, replayed messages, duplicate submissions, resource exhaustion, malicious relays, stale routes, and metadata exposure.

## Current mitigations

- TLS 1.3 transport with certificate validation on the sample client;
- strict fixed-size frame header parsing;
- configured payload limits and a hard maximum;
- reserved flags rejected;
- bounded in-memory deduplication cache;
- explicit warning that the sender label is not authenticated.

## Known gaps

- no LMP identity-document verification;
- no message signatures or end-to-end encryption;
- no persistent deduplication or durable queue;
- no authorization policy wired into message acceptance;
- no rate limiter or production-grade connection admission;
- no formal fuzzing or independent security audit.

Do not expose this alpha to untrusted networks. Do not use it for sensitive communications.
