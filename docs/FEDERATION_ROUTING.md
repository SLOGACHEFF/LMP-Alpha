# LMP Federation Routing — alpha12 draft

## Scope

This milestone defines a signed node-route advertisement and an in-memory cache. It does not define peer discovery, route exchange, forwarding, relay selection, or a complete federated delivery protocol.

## Route record

A version 1 `NodeRouteRecord` contains:

- `principal_id`: the advertised node's canonical `lmp:p:` Principal ID;
- `host` and `port`: a normalized DNS hostname or IP address and TCP port;
- `issued_at` and `expires_at`: Unix timestamps;
- `identity_document_hash`: SHA-256 of the exact canonical identity-document bytes;
- `signature`: Ed25519 signature by the active signing key in that identity document.

The signed input is the domain separator `LMP:ROUTE-RECORD:V1\0` followed by canonical JSON of all unsigned fields, including the signature algorithm. This is an alpha encoding, not a final wire standard.

## Verification requirements

A verifier MUST:

1. Verify the identity document and derive its Principal ID.
2. Require the route Principal ID and identity-document hash to match that document.
3. Validate host and port syntax.
4. Reject records with a lifetime outside 1 second to the configured maximum (at most one hour), expired records, and records issued more than 60 seconds in the future.
5. Verify the Ed25519 signature using the document's active signing public key.
6. Treat the record as a signed claim only, not as proof of reachability or authorization.

The in-memory cache removes expired entries on lookup and prevents a still-valid older record from replacing a newer record for the same Principal ID. It is not persistent and does not exchange records over the network.

## Security limitations

- No TLS exporter/channel binding is implemented in the live handshake.
- Route authenticity does not imply endpoint reachability or safe DNS resolution.
- No route revocation, key rotation, multi-path policy, or route consensus exists.
- No route record should authorize application actions by itself.
- The current record format uses canonical JSON pending a frozen canonical CBOR profile.


## Outbound federation sender (alpha13)

`FederationSender` connects the verified route cache to `DeliveryWorker`. The caller supplies (1) a mapping from recipient Principal IDs to hosting node Principal IDs, (2) the corresponding identity documents, and (3) a route cache populated only after route verification. The sender rechecks route validity before each attempt and accepts only a `STORED` acknowledgement whose message ID matches the outgoing message.

This is direct node submission, not a complete multi-hop relay protocol. A message's `sender` must equal the local identity used for the connection. Third-party-origin forwarding is rejected because alpha13 does not yet define a signed origin envelope, hop limits, or relay authorization. The caller is responsible for provisioning trusted node identities and recipient-to-node mappings; route signatures alone do not establish trust or reachability.
