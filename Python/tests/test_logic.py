import pytest
import base64
import json
from unittest.mock import MagicMock, patch, ANY
from logic.peer_logic import PeerLogic

@pytest.fixture
def mock_app():
    app = MagicMock()
    app.user_id = "Alice"
    app.active_sessions = {}
    app.discovery.peers = {}
    app.auth_manager.pending_handshakes = {}
    app.disk_store.list_encrypted_files.return_value = ["file1.txt"]
    app.disk_store.list_shared_files.return_value = []
    return app

@pytest.fixture
def logic(mock_app):
    return PeerLogic(mock_app)

# --- Handshake Tests ---

def test_initiate_handshake_success(logic, mock_app):
    """Success: Ensure handshake payload contains encoded keys and signature."""
    mock_app.auth_manager.get_public_key.return_value = b"pub_id"
    mock_app.auth_manager.generate_ephemeral_pair.return_value = ("priv_eph", b"pub_eph")
    mock_app.auth_manager.sign.return_value = b"sig"

    packet = logic.initiate_handshake("Bob")

    assert packet["type"] == "HANDSHAKE_INIT"
    assert packet["sender"] == "Alice"
    payload = packet["payload"]
    assert base64.b64decode(payload["identity_key"]) == b"pub_id"
    assert base64.b64decode(payload["ephemeral_share"]) == b"pub_eph"
    assert mock_app.auth_manager.pending_handshakes["Bob"] == "priv_eph"

def test_process_handshake_init_spoof_detection(logic, mock_app):
    """Fail: Block session if signature verification fails (Spoofing)."""
    mock_app.auth_manager.verify_signature.return_value = False
    
    payload = {
        "identity_key": base64.b64encode(b"id").decode(),
        "ephemeral_share": base64.b64encode(b"eph").decode(),
        "signature": base64.b64encode(b"fake_sig").decode()
    }
    
    logic.process_handshake_init("Malory", payload, ("1.2.3.4", 5000))
    
    assert "Malory" not in mock_app.active_sessions
    mock_app.log.assert_called_with("security", ANY)

# --- File Transfer Tests ---

def test_execute_approved_transfer_success(logic, mock_app):
    """Success: Encrypt and send a file with a valid hash and signature."""
    sender = "Bob"
    filename = "test.txt"
    mock_app.active_sessions[sender] = {"encryptor": MagicMock()}
    mock_app.discovery.peers[sender] = {"ip": "1.1.1.1", "port": 5005}
    mock_app.disk_store.get_shared_file_content.return_value = b"hello world"
    mock_app.auth_manager.sign.return_value = b"file_sig"
    mock_app.active_sessions[sender]["encryptor"].encrypt.return_value = b"enc_data"

    logic.execute_approved_transfer(sender, filename)

    mock_app.network.send_message.assert_called_once()
    args = mock_app.network.send_message.call_args[0]
    packet = args[2]
    
    assert packet["type"] == "TRANSFER_ACCEPT"
    assert packet["payload"]["filename"] == filename
    assert base64.b64decode(packet["payload"]["data"]) == b"enc_data"
    assert base64.b64decode(packet["payload"]["signature"]) == b"file_sig"

def test_handle_transfer_accept_integrity_fail(logic, mock_app):
    """Fail: Reject incoming file if SHA-256 hash does not match."""
    sender = "Bob"
    session_mock = {
        "peer_identity": b"bob_pub",
        "encryptor": MagicMock()
    }
    mock_app.active_sessions[sender] = session_mock
    mock_app.auth_manager.verify_signature.return_value = True
    
    session_mock["encryptor"].decrypt.return_value = b"wrong data"
    
    payload = {
        "filename": "virus.exe",
        "sha256": "correct_hash_expected",
        "data": base64.b64encode(b"some_data").decode(),
        "signature": base64.b64encode(b"sig").decode()
    }

    logic.handle_transfer_accept(sender, payload)

    mock_app.log.assert_any_call("security", "Integrity hash mismatch!")
    mock_app.disk_store.save_to_vault.assert_not_called()

# --- Identity Rotation Tests ---

def test_rotate_identity_broadcast(logic, mock_app):
    """Success: Rotate keys and notify all known peers."""
    mock_app.discovery.peers = {
        "Bob": {"ip": "1.1.1.1", "port": 5005},
        "Charlie": {"ip": "2.2.2.2", "port": 5005}
    }
    mock_app.auth_manager.migrate_identity.return_value = (b"old", b"new", b"sig")

    logic.rotate_identity()

    assert mock_app.network.send_message.call_count == 2
    mock_app.log.assert_any_call("security", "Identity rotated and broadcasted.")

def test_process_key_migration_forgery(logic, mock_app):
    """Fail: Pop active session if key migration signature is forged."""
    sender = "Bob"
    mock_app.active_sessions[sender] = {"peer_identity": b"old_key"}
    mock_app.auth_manager.verify_signature.return_value = False

    payload = {
        "new_identity_key": base64.b64encode(b"new").decode(),
        "signature": base64.b64encode(b"fake").decode()
    }

    logic.process_key_migration(sender, payload)

    assert sender not in mock_app.active_sessions
    mock_app.log.assert_any_call("security", f"Forged migration from {sender}!")

# --- Lifecycle Tests ---

def test_handle_peer_left_cleanup(logic, mock_app):
    """Success: Clean up sessions and pending transfers when peer leaves."""
    sender = "Bob"
    mock_app.active_sessions[sender] = {}
    mock_app.discovery.peers[sender] = {}
    mock_app.pending_transfer = {"sender": sender}
    
    logic.handle_peer_left(sender)
    
    assert sender not in mock_app.active_sessions
    assert sender not in mock_app.discovery.peers
    assert mock_app.pending_transfer is None
    assert mock_app.awaiting_consent is False