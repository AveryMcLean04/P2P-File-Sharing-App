import pytest
import base64
from unittest.mock import MagicMock

# --- SUCCESS CASES ---

def test_handshake_flow_success(mock_app):
    """SUCCESS: Verify Alice completes a handshake when Bob provides valid crypto."""
    bob_id = "Bob"
    mock_app.auth_manager.pending_handshakes[bob_id] = b"alice_eph_priv"
    mock_app.auth_manager.verify_signature.return_value = True
    mock_app.auth_manager.derive_shared_secret.return_value = b"shared_secret"
    
    payload = {
        "ephemeral_key": base64.b64encode(b"bob_pub").decode(),
        "signature": base64.b64encode(b"bob_sig").decode(),
        "identity_key": base64.b64encode(b"B"*32).decode()
    }
    
    mock_app.logic.process_handshake_response(bob_id, payload)
    
    assert bob_id in mock_app.active_sessions
    assert mock_app.active_sessions[bob_id]["status"] == "SECURE-SESSION"

def test_logic_file_list_response_success(mock_app, capsys):
    """SUCCESS: Verify that receiving a file list displays the catalog."""
    payload = {"files": ["photo.jpg", "notes.txt"]}
    mock_app.logic.process_file_list_response("Bob", payload)
    
    captured = capsys.readouterr()
    assert "photo.jpg" in captured.out
    assert "notes.txt" in captured.out

# --- FAILURE CASES ---

def test_handshake_signature_verification_failure(mock_app):
    """FAILURE: Verify handshake is aborted if the signature is invalid."""
    bob_id = "Attacker"
    mock_app.auth_manager.verify_signature.return_value = False
    
    payload = {
        "ephemeral_key": base64.b64encode(b"fake").decode(),
        "signature": base64.b64encode(b"bad_sig").decode(),
        "identity_key": base64.b64encode(b"C"*32).decode()
    }
    
    mock_app.logic.process_handshake_response(bob_id, payload)
    
    assert bob_id not in mock_app.active_sessions

def test_chat_decryption_failure(mock_app):
    """FAILURE: Verify handling of malformed/tampered encrypted messages."""
    sender = "Alice"
    mock_encryptor = MagicMock()
    mock_encryptor.decrypt.side_effect = Exception("Decryption failed")
    
    mock_app.active_sessions[sender] = {
        "status": "SECURE-SESSION",
        "encryptor": mock_encryptor
    }

    garbage_payload = "Z2FyYmFnZQ==" 
    mock_app.logic.process_chat_message(sender, garbage_payload)
    
    mock_app.log.assert_called_with("error", f"Failed to decrypt message from {sender}.")

def test_logic_missing_pending_handshake_failure(mock_app):
    """FAILURE: Verify logic handles responses for handshakes it didn't start."""
    mock_app.auth_manager.pending_handshakes = {} 
    
    payload = {
        "ephemeral_key": "...", 
        "signature": "...", 
        "identity_key": "..."
    }
    mock_app.logic.process_handshake_response("Bob", payload)
    
    assert "Bob" not in mock_app.active_sessions