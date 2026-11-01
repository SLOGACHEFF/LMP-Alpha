from dataclasses import replace

import pytest

from lmp_core.errors import AuthenticationError, AuthorizationError
from lmp_core.messaging.envelope import create_signed_envelope
from lmp_core.messaging.relay import RelayTrace, verify_relay_trace
from lmp_core.security.identity import IdentityKeyPair

NOW = 1_800_000_000


def _setup():
    origin = IdentityKeyPair.generate()
    origin_doc = origin.create_initial_document(created_at=NOW)
    relay_a = IdentityKeyPair.generate()
    relay_a_doc = relay_a.create_initial_document(created_at=NOW)
    relay_b = IdentityKeyPair.generate()
    relay_b_doc = relay_b.create_initial_document(created_at=NOW)
    envelope = create_signed_envelope(
        origin, origin_doc, message_id="relay-test-1", recipient="lmp:p:recipient",
        body={"hello": "world"}, ttl_seconds=3600, now=NOW,
    )
    return envelope, relay_a, relay_a_doc, relay_b, relay_b_doc


def test_signed_relay_trace_verifies_and_preserves_origin_envelope():
    envelope, a, a_doc, b, b_doc = _setup()
    trace = RelayTrace().append(envelope, a, a_doc, now=NOW, allowed_relays={a.principal_id_text})
    trace = trace.append(envelope, b, b_doc, now=NOW + 1,
                         allowed_relays={a.principal_id_text, b.principal_id_text})
    assert verify_relay_trace(envelope, trace,
                              allowed_relays={a.principal_id_text, b.principal_id_text},
                              now=NOW + 2) == (a.principal_id_text, b.principal_id_text)
    assert envelope.origin_principal_id not in (a.principal_id_text, b.principal_id_text)


def test_relay_trace_rejects_untrusted_relay_and_missing_allowlist():
    envelope, a, a_doc, _, _ = _setup()
    with pytest.raises(AuthorizationError, match="allow-list"):
        RelayTrace().append(envelope, a, a_doc, now=NOW)
    with pytest.raises(AuthorizationError, match="not authorized"):
        RelayTrace().append(envelope, a, a_doc, now=NOW, allowed_relays=set())


def test_relay_trace_rejects_loop_and_hop_limit():
    envelope, a, a_doc, b, b_doc = _setup()
    trace = RelayTrace().append(envelope, a, a_doc, now=NOW,
                                allowed_relays={a.principal_id_text}, max_hops=1)
    with pytest.raises(AuthorizationError, match="loop"):
        trace.append(envelope, a, a_doc, now=NOW + 1,
                     allowed_relays={a.principal_id_text}, max_hops=3)
    with pytest.raises(AuthorizationError, match="hop limit"):
        trace.append(envelope, b, b_doc, now=NOW + 1,
                     allowed_relays={a.principal_id_text, b.principal_id_text}, max_hops=1)


def test_relay_trace_rejects_tampering_and_chain_reordering():
    envelope, a, a_doc, b, b_doc = _setup()
    trace = RelayTrace().append(envelope, a, a_doc, now=NOW,
                                allowed_relays={a.principal_id_text})
    trace = trace.append(envelope, b, b_doc, now=NOW + 1,
                         allowed_relays={a.principal_id_text, b.principal_id_text})
    changed = replace(trace.receipts[0], relay_principal_id="lmp:p:forged")
    bad_trace = RelayTrace((changed, trace.receipts[1]))
    with pytest.raises((AuthenticationError, AuthorizationError)):
        verify_relay_trace(envelope, bad_trace,
                           allowed_relays={a.principal_id_text, b.principal_id_text}, now=NOW + 2)
    reversed_trace = RelayTrace(tuple(reversed(trace.receipts)))
    with pytest.raises((AuthenticationError, AuthorizationError)):
        verify_relay_trace(envelope, reversed_trace,
                           allowed_relays={a.principal_id_text, b.principal_id_text}, now=NOW + 2)


def test_relay_trace_rejects_receipt_for_another_envelope():
    envelope, a, a_doc, _, _ = _setup()
    trace = RelayTrace().append(envelope, a, a_doc, now=NOW,
                                allowed_relays={a.principal_id_text})
    other_origin = IdentityKeyPair.generate()
    other_doc = other_origin.create_initial_document(created_at=NOW)
    other_envelope = create_signed_envelope(
        other_origin, other_doc, message_id="different", recipient="lmp:p:recipient",
        body="not the same", ttl_seconds=3600, now=NOW,
    )
    with pytest.raises(AuthenticationError):
        verify_relay_trace(other_envelope, trace,
                           allowed_relays={a.principal_id_text}, now=NOW + 1)


def test_relay_trace_canonical_roundtrip_and_rejects_noncanonical_bytes():
    import pytest
    from lmp_core.errors import AuthenticationError
    from lmp_core.messaging.relay import RelayTrace
    from lmp_core.security.identity import IdentityKeyPair
    from lmp_core.messaging.envelope import create_signed_envelope

    origin = IdentityKeyPair.generate()
    relay = IdentityKeyPair.generate()
    origin_doc = origin.create_initial_document()
    envelope = create_signed_envelope(origin, origin_doc, message_id="wire-roundtrip",
                                      recipient="recipient", body={"text": "hello"}, now=1000)
    trace = RelayTrace().append(envelope, relay, relay.create_initial_document(),
                                now=1001, allowed_relays={relay.principal_id_text})
    encoded = trace.to_bytes()
    assert RelayTrace.from_bytes(encoded) == trace
    with pytest.raises(AuthenticationError):
        RelayTrace.from_bytes(encoded + b" ")
