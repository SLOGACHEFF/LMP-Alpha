# LMP Federation Route Failover (alpha23)

The federation outbox worker can now accept an optional `route_failover(item,
failed_next_hop)` callback. This callback is a policy hook, not an automatic
discovery protocol: the deployment chooses an alternate Principal ID based on
its own configured routing information.

When the current route record or its identity document is missing, the worker:

1. asks the configured callback for an alternate next hop;
2. rejects a candidate equal to the failed hop, the origin, or any relay already
   present in the signed trace;
3. requires a non-expired signed route record and configured identity document
   for the candidate;
4. persists the new next hop under the current lease fencing token;
5. releases the lease for an immediate retry.

If no suitable candidate is returned, the existing delayed retry path remains in
place. Invalid signatures are not treated as ordinary route misses and do not
trigger failover.

## Limitations

- The callback must be supplied by the deployment; no route discovery or global
  shortest-path calculation is implemented.
- This first failover path handles missing route metadata. It does not yet
  automatically switch routes after an established connection fails.
- A route advertisement proves signed endpoint ownership, not reachability or
  permission to forward a specific message. The normal TLS/LMP authentication
  and receiver relay policy still apply.
- Loop checks use the origin and relay identities already in the trace. Network
  retries remain at-least-once and rely on recipient deduplication.
