import pytest
import base64
import hashlib
from unittest.mock import MagicMock, patch

# --- 1. Handshake & Security Tests ---

def test_full_handshake_flow(mock_app):
    """Verifies initiate -> process_init -> process_response math & state."""
    alice = mock_app
    bob_id = "Bob"
    bob_addr = ("127.0.0.1", 5001)

    # Alice initiates
    init_payload = alice.logic.initiate_handshake(bob_id)
    assert init_payload["type"] == "HANDSHAKE_INIT"
    
    # Simulate Bob processing Alice's init and sending a response
    # We use Alice's own auth_manager to simulate Bob's side of the math
    alice_eph_pub = base64.b64decode(init_payload["payload"]["ephemeral_share"])
    bob_priv, bob_pub = alice.auth_manager.generate_ephemeral_pair()
    bob_sig = alice.auth_manager.sign(bob_pub)
    
    response_payload = {
        "ephemeral_key": base64.b64encode(bob_pub).decode(),
        "signature": base64.b64encode(bob_sig).decode(),
        "identity_key": base64.b64encode(alice.auth_manager.get_public_key()).decode()
    }

    # Alice processes Bob's response
    alice.logic.process_handshake_response(bob_id, response_payload)
    
    assert bob_id in alice.active_sessions
    assert alice.active_sessions[bob_id]["status"] == "SECURE-SESSION"

def test_handshake_signature_failure(mock_app):
    """Ensures handshake aborts if the identity signature is invalid."""
    alice = mock_app
    alice.auth_manager.verify_signature.return_value = False
    
    alice.logic.process_handshake_init("Attacker", {}, ("1.1.1.1", 80))
    assert "Attacker" not in alice.active_sessions

# --- 2. Messaging & Catalog Tests ---

def test_chat_decryption_failure_logging(secure_session, capsys):
    """Tests that bad ciphertexts don't crash the app, but log an error."""
    app, peer = secure_session
    app.active_sessions[peer]["encryptor"].decrypt.side_effect = Exception("Decryption failed")
    
    app.logic.process_chat_message(peer, base64.b64encode(b"garbage").decode())
    captured = capsys.readouterr()
    assert "[ERROR]" in captured.out

def test_handle_list_request(mock_app):
    """Tests that we correctly send our file list to a peer."""
    mock_app.disk_store = MagicMock()
    mock_app.disk_store.list_encrypted_files.return_value = ["file1.txt", "file2.jpg"]
    mock_app.discovery.peers["Bob"] = {"ip": "1.2.3.4", "port": 5000}
    
    mock_app.logic.handle_list_request("Bob")
    
    # Check if network sent the correct payload
    args, _ = mock_app.network.send_message.call_args
    assert args[2]["type"] == "FILE_LIST_RESPONSE"
    assert "file1.txt" in args[2]["payload"]["files"]

# --- 3. Transfer Consent & Execution Tests ---

def test_initiate_file_request(mock_app):
    """Tests the 'Pull' initiation (TRANSFER_REQUEST)."""
    mock_app.discovery.peers["Bob"] = {"ip": "1.2.3.4", "port": 5000}
    mock_app.logic.initiate_file_request("Bob", "data.zip")
    
    args, _ = mock_app.network.send_message.call_args
    assert args[2]["type"] == "TRANSFER_REQUEST"
    assert args[2]["payload"]["filename"] == "data.zip"

def test_handle_push_proposal(mock_app):
    """Tests that an incoming 'Send' proposal sets the UI to awaiting consent."""
    payload = {"filename": "holiday.mp4"}
    mock_app.logic.handle_push_proposal("Bob", payload)
    
    assert mock_app.awaiting_consent is True
    assert mock_app.pending_transfer["type"] == "PUSH"

def test_execute_approved_transfer_success(secure_session):
    """Tests the full logic of sending a file: Export -> Sign -> Encrypt -> Send."""
    app, peer = secure_session
    filename = "test.txt"
    raw_data = b"hello world"
    
    app.disk_store = MagicMock()
    app.disk_store.list_shared_files.return_value = []
    app.disk_store.get_shared_file_content.return_value = raw_data
    app.discovery.peers[peer] = {"ip": "1.2.3.4", "port": 5000}
    
    app.logic.execute_approved_transfer(peer, filename)
    
    # Verify export was triggered
    app.disk_store.export_from_vault_to_shared.assert_called_with(filename)
    # Verify network message contains encrypted data and signature
    args, _ = app.network.send_message.call_args
    assert args[2]["type"] == "TRANSFER_ACCEPT"
    assert "data" in args[2]["payload"]
    assert "signature" in args[2]["payload"]

def test_handle_transfer_accept_integrity_check(secure_session, capsys):
    """Tests that receiving a file with a mismatched hash triggers an alert."""
    app, peer = secure_session
    app.disk_store = MagicMock()
    app.auth_manager.verify_signature.return_value = True
    
    # Simulate a payload where the data doesn't match the SHA256 provided
    payload = {
        "filename": "evil.exe",
        "data": base64.b64encode(b"enc_wrong_data").decode(),
        "sha256": "correct_hash_of_something_else",
        "signature": base64.b64encode(b"valid_sig").decode()
    }
    
    app.logic.handle_transfer_accept(peer, payload)
    captured = capsys.readouterr()
    assert "INTEGRITY ALERT" in captured.out
    app.disk_store.save_to_vault.assert_not_called()

# --- 4. Redundancy & Cleanup Tests ---

def test_handle_redundancy_query(mock_app):
    """Tests that we offer a file if we have it in our vault."""
    filename = "shared_doc.pdf"
    mock_app.disk_store = MagicMock()
    mock_app.disk_store.list_encrypted_files.return_value = [filename]
    mock_app.discovery.peers["Charlie"] = {"ip": "5.5.5.5", "port": 5000}
    
    mock_app.logic.handle_redundancy_query("Charlie", {"filename": filename})
    
    args, _ = mock_app.network.send_message.call_args
    assert args[2]["type"] == "REDUNDANCY_OFFER"

def test_handle_peer_left(secure_session):
    """Ensures peer data is wiped from both sessions and discovery on disconnect."""
    app, peer = secure_session
    app.discovery.peers[peer] = {"ip": "1.1.1.1"}
    
    app.logic.handle_peer_left(peer)
    
    assert peer not in app.active_sessions
    assert peer not in app.discovery.peers