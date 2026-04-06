import pytest
import base64
from unittest.mock import MagicMock, ANY
from src.logic.peer_logic import PeerLogic

@pytest.fixture
def mock_app():
    app = MagicMock()
    app.user_id = "Alice"
    app.active_sessions = {}
    app.discovery.peers = {}
    app.auth_manager.pending_handshakes = {}
    
    app.disk_store.list_encrypted_files.return_value = ["file1.txt"]
    app.disk_store.list_shared_files.return_value = []
    
    app.disk_store.decrypt_to_system.side_effect = lambda f, d: f == "file1.txt"
    
    return app

@pytest.fixture
def logic(mock_app):
    return PeerLogic(mock_app)

def test_initiate_handshake_success(logic, mock_app):
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

def test_process_handshake_init_fail(logic, mock_app):
    mock_app.auth_manager.verify_signature.return_value = False
    
    payload = {
        "identity_key": base64.b64encode(b"id").decode(),
        "ephemeral_share": base64.b64encode(b"eph").decode(),
        "signature": base64.b64encode(b"fake_sig").decode()
    }
    
    logic.process_handshake_init("Malory", payload, ("1.2.3.4", 5000))
    
    assert "Malory" not in mock_app.active_sessions
    mock_app.log.assert_called_with("security", ANY)

def test_execute_approved_transfer_success(logic, mock_app):
    sender = "Bob"
    filename = "test.txt"
    mock_app.active_sessions[sender] = {"encryptor": MagicMock()}
    mock_app.discovery.peers[sender] = {"ip": "1.1.1.1", "port": 5005}
    mock_app.disk_store.get_shared_file_content.return_value = b"hello world"
    mock_app.auth_manager.sign.return_value = b"file_sig"
    mock_app.active_sessions[sender]["encryptor"].encrypt.return_value = b"enc_data"

    logic.execute_approved_transfer(sender, filename)

    mock_app.network.send_message.assert_called_once()
    packet = mock_app.network.send_message.call_args[0][2]
    
    assert packet["type"] == "TRANSFER_ACCEPT"
    assert packet["payload"]["filename"] == filename
    assert base64.b64decode(packet["payload"]["data"]) == b"enc_data"
    assert base64.b64decode(packet["payload"]["signature"]) == b"file_sig"

def test_handle_transfer_accept_fail(logic, mock_app):
    sender = "Bob"
    session_mock = {"peer_identity": b"bob_pub", "encryptor": MagicMock()}
    mock_app.active_sessions[sender] = session_mock
    mock_app.auth_manager.verify_signature.return_value = True
    
    session_mock["encryptor"].decrypt.return_value = b"tampered data"
    mock_app.disk_store.encryptor.get_hash.return_value = "actual_hash_123"
    
    payload = {
        "filename": "virus.exe",
        "sha256": "expected_hash_456",
        "data": base64.b64encode(b"some_data").decode(),
        "signature": base64.b64encode(b"sig").decode()
    }

    logic.handle_transfer_accept(sender, payload)

    found = any("Integrity hash mismatch" in call.args[1] for call in mock_app.log.call_args_list if call.args[0] == "security")
    assert found
    mock_app.disk_store.save_to_vault.assert_not_called()

def test_manual_decryption_gate_success(logic, mock_app):
    result = mock_app.disk_store.decrypt_to_system("file1.txt", "/tmp/out")
    assert result is True

def test_manual_decryption_gate_fail(logic, mock_app):
    result = mock_app.disk_store.decrypt_to_system("missing.txt", "/tmp/out")
    assert result is False

def test_rotate_identity_success(logic, mock_app):
    mock_app.discovery.peers = {
        "Bob": {"ip": "1.1.1.1", "port": 5005},
        "Charlie": {"ip": "2.2.2.2", "port": 5005}
    }
    mock_app.auth_manager.migrate_identity.return_value = (b"old", b"new", b"sig")

    logic.rotate_identity()

    assert mock_app.network.send_message.call_count == 2
    mock_app.log.assert_any_call("security", "Identity rotated and broadcasted.")

def test_process_key_migration_fail(logic, mock_app):
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

def test_handle_peer_left_success(logic, mock_app):
    sender = "Bob"
    mock_app.active_sessions[sender] = {}
    mock_app.discovery.peers[sender] = {}
    mock_app.pending_transfer = {"sender": sender}
    
    logic.handle_peer_left(sender)
    
    assert sender not in mock_app.active_sessions
    assert sender not in mock_app.discovery.peers
    assert mock_app.pending_transfer is None
    assert mock_app.awaiting_consent is False