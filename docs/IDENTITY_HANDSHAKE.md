# LMP Identity Handshake (alpha8)

This document describes the first integration of LMP identity proof into the TCP/TLS node.
It is an experimental profile, not a stable interoperability specification.

## Flow

1. The client establishes TLS 1.3 with normal certificate and hostname validation.
2. `HELLO` carries a 32-byte client nonce and the client's signed genesis identity document.
3. `HELLO_ACK` carries a 32-byte server nonce, the server's signed identity document, and a server Ed25519 proof over the client nonce and handshake transcript.
4. Both sides calculate the same transcript binding from both nonces and both canonical identity-document hashes.
5. The client verifies the server identity against a configured `lmp:p:` Principal ID pin and verifies the server proof, then sends `IDENTITY_PROOF` over the server nonce and transcript binding.
6. The server verifies the client's proof, optionally checks its Principal ID against `allowed_principals`, and returns `IDENTITY_ACCEPT`.
7. Only after this exchange does the server process `MESSAGE` frames. The message `sender` must match the authenticated Principal ID.
8. The client checks response request IDs and verifies that `IDENTITY_ACCEPT` names both the expected server Principal ID and its own Principal ID. Both client and server require a negotiated TLS 1.3 session.

## Trust and limitations

- TLS certificate validation and LMP identity verification are independent checks.
- The server Principal ID must be pinned by the client. Do not silently trust an unknown key.
- `allowed_principals=None` allows any cryptographically authenticated client identity; deployments should configure an allowlist where membership matters.
- This transcript binding is not a TLS exporter/channel binding. It binds the LMP handshake data, but does not cryptographically bind the LMP proof to TLS session secrets. TLS 1.3 negotiation is checked explicitly, but channel binding remains future work.
- Identity documents currently support genesis revision 1 only. Key rotation, revocation, recovery, device identities, durable delivery, and application-level recipient authorization are not implemented.
- The encrypted local key file is an alpha format. Keep backups secure and use a strong password.
- Never deploy this alpha as a production messaging service.

## Alpha8 hardening and tests

- `NodeConfig` rejects zero or excessive frame limits, invalid dedup capacities, empty/oversized protocol versions, and malformed allowlist entries.
- Client response correlation IDs are checked; the final server confirmation must identify both expected principals.
- The node checks that the negotiated TLS session is TLS 1.3, rather than relying only on the configured minimum version.
- `tests/test_node_security.py` exercises config rejection and loopback mutual-authentication / allowlist behavior. Run it after installing `.[test]`; the current development environment may not include `cbor2`.
