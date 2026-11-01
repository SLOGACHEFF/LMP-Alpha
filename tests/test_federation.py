import json

import pytest

from lmp_core.errors import AuthenticationError
from lmp_core.network import RouteCache, create_route_record, verify_route_record
from lmp_core.network.federation import NodeRouteRecord
from lmp_core.security.identity import IdentityDocument, IdentityKeyPair


def test_signed_route_record_round_trip_and_verify():
    keys = IdentityKeyPair.generate()
    doc = keys.create_initial_document(created_at=1_800_000_000)
    record = create_route_record(keys, doc, "EXAMPLE.COM.", 7443, ttl_seconds=120, now=1_800_000_100)
    parsed = NodeRouteRecord.from_dict(json.loads(record.to_bytes()))
    assert parsed == record
    assert parsed.host == "example.com"
    assert verify_route_record(parsed, doc, now=1_800_000_110) == parsed


def test_route_signature_rejects_host_tampering():
    keys = IdentityKeyPair.generate()
    doc = keys.create_initial_document(created_at=1_800_000_000)
    record = create_route_record(keys, doc, "node.example", 7443, now=1_800_000_100)
    tampered = NodeRouteRecord(record.version, record.principal_id, "evil.example", record.port,
                               record.issued_at, record.expires_at, record.identity_document_hash,
                               record.signature)
    with pytest.raises(AuthenticationError):
        verify_route_record(tampered, doc, now=1_800_000_110)


def test_route_record_rejects_another_identity_document():
    keys = IdentityKeyPair.generate()
    other = IdentityKeyPair.generate()
    doc = keys.create_initial_document(created_at=1_800_000_000)
    other_doc = other.create_initial_document(created_at=1_800_000_000)
    record = create_route_record(keys, doc, "node.example", 7443, now=1_800_000_100)
    with pytest.raises(AuthenticationError):
        verify_route_record(record, other_doc, now=1_800_000_110)


def test_route_record_expiry_and_future_issuance_are_rejected():
    keys = IdentityKeyPair.generate()
    doc = keys.create_initial_document(created_at=1_800_000_000)
    record = create_route_record(keys, doc, "node.example", 7443, ttl_seconds=10, now=1000)
    with pytest.raises(AuthenticationError):
        verify_route_record(record, doc, now=1010)
    with pytest.raises(AuthenticationError):
        verify_route_record(record, doc, now=900)


def test_route_creation_validates_endpoint_and_ttl():
    keys = IdentityKeyPair.generate()
    doc = keys.create_initial_document(created_at=1_800_000_000)
    with pytest.raises(ValueError):
        create_route_record(keys, doc, "https://node.example/path", 7443)
    with pytest.raises(ValueError):
        create_route_record(keys, doc, "node.example", 70000)
    with pytest.raises(ValueError):
        create_route_record(keys, doc, "node.example", 7443, ttl_seconds=3601)


def test_route_cache_verifies_and_expires_records():
    keys = IdentityKeyPair.generate()
    doc = keys.create_initial_document(created_at=1_800_000_000)
    record = create_route_record(keys, doc, "node.example", 7443, ttl_seconds=10, now=1000)
    cache = RouteCache()
    cache.add(record, doc, now=1001)
    assert cache.get(record.principal_id, now=1009) == record
    assert cache.get(record.principal_id, now=1010) is None
    assert len(cache) == 0


def test_route_record_rejects_unknown_fields():
    keys = IdentityKeyPair.generate()
    doc = keys.create_initial_document(created_at=1_800_000_000)
    record = create_route_record(keys, doc, "node.example", 7443, now=1000)
    data = json.loads(record.to_bytes())
    data["unreviewed"] = True
    with pytest.raises(ValueError):
        NodeRouteRecord.from_dict(data)


def test_route_cache_rejects_rollback_to_older_valid_record():
    keys = IdentityKeyPair.generate()
    doc = keys.create_initial_document(created_at=1_800_000_000)
    older = create_route_record(keys, doc, "old.example", 7443, ttl_seconds=300, now=1000)
    newer = create_route_record(keys, doc, "new.example", 7443, ttl_seconds=300, now=1010)
    cache = RouteCache()
    cache.add(newer, doc, now=1020)
    with pytest.raises(AuthenticationError):
        cache.add(older, doc, now=1020)
    assert cache.get(newer.principal_id, now=1020) == newer
