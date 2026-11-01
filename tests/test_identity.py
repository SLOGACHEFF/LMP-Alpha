import json
import pytest
from lmp_core.security.identity import IdentityDocument, IdentityKeyPair, verify_document_bytes, verify_identity_document, verify_peer_proof
from lmp_core.errors import AuthenticationError
from lmp_core.security.handshake import IdentityChallenge


def test_generated_identity_document_verifies():
    keys = IdentityKeyPair.generate()
    doc = keys.create_initial_document(created_at=1_800_000_000)
    assert verify_identity_document(doc) == keys.principal_id
    assert doc.revision == 1 and doc.previous_document_hash is None
    assert keys.principal_id_text.startswith("lmp:p:")
    assert "=" not in keys.principal_id_text


def test_identity_document_round_trip_is_canonical():
    keys = IdentityKeyPair.generate()
    doc = keys.create_initial_document(created_at=1_800_000_000)
    parsed, principal = verify_document_bytes(doc.to_bytes())
    assert parsed == doc and principal == keys.principal_id


def test_tampered_identity_document_fails():
    keys = IdentityKeyPair.generate()
    doc = keys.create_initial_document(created_at=1_800_000_000)
    changed = IdentityDocument(doc.version, doc.principal_id, doc.revision, doc.root_public_key,
                               doc.signing_public_key, doc.created_at + 1,
                               doc.previous_document_hash, doc.signature)
    with pytest.raises(AuthenticationError):
        verify_identity_document(changed)


def test_principal_id_cannot_be_replaced_independently():
    keys = IdentityKeyPair.generate()
    doc = keys.create_initial_document(created_at=1_800_000_000)
    changed = IdentityDocument(doc.version, "A" * len(doc.principal_id), doc.revision,
                               doc.root_public_key, doc.signing_public_key, doc.created_at,
                               doc.previous_document_hash, doc.signature)
    with pytest.raises(AuthenticationError):
        verify_identity_document(changed)


def test_unknown_fields_are_rejected():
    keys = IdentityKeyPair.generate()
    data = json.loads(keys.create_initial_document(created_at=1_800_000_000).to_bytes())
    data["unreviewed_extension"] = True
    with pytest.raises(ValueError):
        IdentityDocument.from_dict(data)


def test_challenge_proof_verifies_for_expected_session():
    keys = IdentityKeyPair.generate()
    doc = keys.create_initial_document(created_at=1_800_000_000)
    challenge = bytes(range(32))
    binding = b"test-session:initiator-nonce|responder-nonce"
    signature = keys.sign_challenge(doc, challenge, binding)
    assert verify_peer_proof(doc, challenge, binding, signature) == keys.principal_id


@pytest.mark.parametrize("challenge,binding", [
    (b"x" * 32, b"session-A"),
    (bytes(range(32)), b"session-B"),
])
def test_challenge_proof_fails_if_challenge_or_binding_changes(challenge, binding):
    keys = IdentityKeyPair.generate()
    doc = keys.create_initial_document(created_at=1_800_000_000)
    signature = keys.sign_challenge(doc, bytes(range(32)), b"session-A")
    with pytest.raises(AuthenticationError):
        verify_peer_proof(doc, challenge, binding, signature)


def test_challenge_proof_rejects_wrong_signing_key():
    keys = IdentityKeyPair.generate()
    other = IdentityKeyPair.generate()
    doc = keys.create_initial_document(created_at=1_800_000_000)
    other_doc = other.create_initial_document(created_at=1_800_000_000)
    signature = other.sign_challenge(other_doc, bytes(range(32)), b"session-A")
    with pytest.raises(AuthenticationError):
        verify_peer_proof(doc, bytes(range(32)), b"session-A", signature)


def test_challenge_proof_rejects_invalid_challenge_size():
    keys = IdentityKeyPair.generate()
    doc = keys.create_initial_document(created_at=1_800_000_000)
    with pytest.raises(AuthenticationError):
        keys.sign_challenge(doc, b"short", b"session-A")


def test_identity_challenge_is_single_use():
    keys = IdentityKeyPair.generate()
    doc = keys.create_initial_document(created_at=1_800_000_000)
    challenge = IdentityChallenge(session_binding=b"fresh-connection-context")
    signature = keys.sign_challenge(doc, challenge.challenge, challenge.session_binding)
    assert challenge.verify_response(doc, signature) == keys.principal_id
    assert challenge.consumed
    with pytest.raises(AuthenticationError):
        challenge.verify_response(doc, signature)


def test_failed_identity_challenge_cannot_be_retried():
    keys = IdentityKeyPair.generate()
    doc = keys.create_initial_document(created_at=1_800_000_000)
    challenge = IdentityChallenge(session_binding=b"fresh-connection-context")
    with pytest.raises(AuthenticationError):
        challenge.verify_response(doc, b"invalid")
    assert challenge.consumed
    with pytest.raises(AuthenticationError):
        challenge.verify_response(doc, b"invalid")


def test_handshake_transcript_binds_both_nonces_and_documents():
    from lmp_core.security.handshake import HandshakeTranscript
    client = IdentityKeyPair.generate()
    server = IdentityKeyPair.generate()
    client_doc = client.create_initial_document(created_at=1_800_000_000)
    server_doc = server.create_initial_document(created_at=1_800_000_001)
    transcript = HandshakeTranscript(b"c" * 32, b"s" * 32, client_doc, server_doc)
    assert len(transcript.binding) == 32
    assert transcript.binding == HandshakeTranscript(
        b"c" * 32, b"s" * 32, client_doc, server_doc
    ).binding
    assert transcript.binding != HandshakeTranscript(
        b"x" * 32, b"s" * 32, client_doc, server_doc
    ).binding
    assert transcript.binding != HandshakeTranscript(
        b"c" * 32, b"s" * 32, server_doc, client_doc
    ).binding


def test_handshake_transcript_rejects_invalid_nonces():
    from lmp_core.security.handshake import HandshakeTranscript
    keys = IdentityKeyPair.generate()
    doc = keys.create_initial_document(created_at=1_800_000_000)
    with pytest.raises(ValueError):
        HandshakeTranscript(b"short", b"s" * 32, doc, doc)
    with pytest.raises(ValueError):
        HandshakeTranscript(b"c" * 32, b"c" * 32, doc, doc)


def test_encrypted_identity_keypair_round_trip(tmp_path):
    keys = IdentityKeyPair.generate()
    path = tmp_path / "identity.json"
    keys.save_encrypted(path, "correct horse battery staple")
    loaded = IdentityKeyPair.load_encrypted(path, "correct horse battery staple")
    assert loaded.principal_id == keys.principal_id
    assert loaded.create_initial_document().root_public_key == keys.create_initial_document().root_public_key
    assert path.stat().st_mode & 0o077 == 0


def test_encrypted_identity_keypair_rejects_wrong_password(tmp_path):
    keys = IdentityKeyPair.generate()
    path = tmp_path / "identity.json"
    keys.save_encrypted(path, "correct horse battery staple")
    with pytest.raises(AuthenticationError):
        IdentityKeyPair.load_encrypted(path, "incorrect password")
