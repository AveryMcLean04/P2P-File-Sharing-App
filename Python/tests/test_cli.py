import pytest
from unittest.mock import MagicMock, patch
import base64

# --- SUCCESS CASES ---

def test_cli_help_output(mock_app, capsys):
    """SUCCESS: Verify the help command displays the command table."""
    from ui.cli import AppCLI
    cli = AppCLI(mock_app)
    cli.show_help()
    captured = capsys.readouterr()
    assert "COMMAND" in captured.out
    assert "connect" in captured.out

def test_cmd_list_with_peers(mock_app, capsys):
    """SUCCESS: Verify discovered peers are listed with their session status."""
    from ui.cli import AppCLI
    cli = AppCLI(mock_app)
    
    mock_app.discovery.peers = {"Alice": {"ip": "192.168.1.5", "port": 5000}}
    mock_app.active_sessions = {"Alice": {"status": "SECURE-SESSION"}}
    
    cli.cmd_list()
    captured = capsys.readouterr()
    assert "Alice" in captured.out
    assert "SECURE-SESSION" in captured.out

def test_cmd_connect_initiates_handshake(mock_app):
    """SUCCESS: Verify 'connect <UserID>' triggers the logic and network calls."""
    from ui.cli import AppCLI
    cli = AppCLI(mock_app)
    
    target = "Bob"
    mock_app.discovery.peers = {target: {"ip": "10.0.0.1", "port": 5000}}
    
    mock_app.logic.initiate_handshake.return_value = {"type": "HANDSHAKE"}
    
    cli.cmd_connect(target)
    
    mock_app.logic.initiate_handshake.assert_called_with(target)
    mock_app.network.send_message.assert_called_with("10.0.0.1", 5000, {"type": "HANDSHAKE"})

@patch("builtins.input", side_effect=["Hello Alice"])
def test_cmd_chat_success(mock_input, mock_app):
    """SUCCESS: Verify chat encrypts and sends a message."""
    from ui.cli import AppCLI
    cli = AppCLI(mock_app)
    
    target = "Alice"
    mock_encryptor = MagicMock()
    mock_encryptor.encrypt.return_value = b"encrypted_bytes"
    
    mock_app.active_sessions = {target: {"encryptor": mock_encryptor}}
    mock_app.discovery.peers = {target: {"ip": "1.1.1.1", "port": 5000}}
    
    cli.cmd_chat(target)
    
    sent_args = mock_app.network.send_message.call_args[0]
    payload = sent_args[2]["payload"]
    assert payload == base64.b64encode(b"encrypted_bytes").decode()

# --- FAILURE / EDGE CASES ---

def test_cmd_send_file_not_in_vault(mock_app):
    """FAILURE: Verify 'send' fails if the file doesn't exist locally."""
    from ui.cli import AppCLI
    cli = AppCLI(mock_app)
    
    target = "Alice"
    mock_app.active_sessions = {target: {}}
    mock_app.disk_store.list_encrypted_files.return_value = ["real.txt"]
    
    cli.cmd_send(target, "fake.txt")
    
    mock_app.log.assert_called_with("error", "'fake.txt' not found in local Vault.")

@patch("builtins.input", side_effect=["y"])
def test_cmd_uningest_confirmation(mock_input, mock_app):
    """SUCCESS: Verify file removal requires confirmation."""
    from ui.cli import AppCLI
    cli = AppCLI(mock_app)
    
    cli.cmd_uningest("my_secret.txt")
    
    mock_app.disk_store.uningest_file.assert_called_with("my_secret.txt")