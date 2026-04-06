import pytest
from unittest.mock import MagicMock, patch
from src.ui.cli import AppCLI

@pytest.fixture
def standalone_mock_app():
    """
    Creates a completely isolated mock app. 
    We don't rely on conftest here to avoid import-order pollution.
    """
    app = MagicMock()
    app.user_id = "Alice"
    app.active_sessions = {}
    app.discovery.peers = {}
    app.pending_transfer = None
    app.awaiting_consent = False
    app.logic = MagicMock()
    app.network = MagicMock()
    app.disk_store = MagicMock()
    app.log = MagicMock()
    return app

@pytest.fixture
def cli(standalone_mock_app):
    return AppCLI(standalone_mock_app)

# --- Tests ---

def test_cmd_list_no_peers(cli, standalone_mock_app):
    standalone_mock_app.discovery.peers = {}
    cli.cmd_list()

    standalone_mock_app.log.assert_any_call("system", "No active peers found on local network.")

def test_cmd_connect_success(cli, standalone_mock_app):
    standalone_mock_app.discovery.peers = {"Bob": {"ip": "127.0.0.1", "port": 5005}}
    standalone_mock_app.logic.initiate_handshake.return_value = {"type": "HELLO"}
    standalone_mock_app.network.send_message.return_value = True
    
    cli.cmd_connect("Bob")
    
    assert standalone_mock_app.logic.initiate_handshake.called
    assert standalone_mock_app.network.send_message.called

def test_cmd_chat_denied_without_session(cli, standalone_mock_app):
    standalone_mock_app.active_sessions = {}
    cli.cmd_chat("Bob")
    standalone_mock_app.log.assert_any_call("error", "Access Denied: No secure session with Bob.")

def test_cmd_ingest(cli, standalone_mock_app):
    cli.cmd_ingest("test_file.txt")
    standalone_mock_app.disk_store.ingest_file.assert_called_once_with("test_file.txt")

def test_cmd_chat_success(cli, standalone_mock_app):
    mock_encryptor = MagicMock()
    mock_encryptor.encrypt.return_value = b"encrypted_data"
    
    standalone_mock_app.active_sessions = {"Bob": {"encryptor": mock_encryptor}}
    standalone_mock_app.discovery.peers = {"Bob": {"ip": "127.0.0.1", "port": 5005}}
    standalone_mock_app.user_id = "Alice"
    
    with patch("builtins.input", return_value="Hello"):
        cli.cmd_chat("Bob")
    
    assert mock_encryptor.encrypt.called
    assert standalone_mock_app.network.send_message.called
    
    args = standalone_mock_app.network.send_message.call_args[0]
    assert args[0] == "127.0.0.1"
    assert args[2]["type"] == "CHAT_MESSAGE"

def test_cmd_deny(cli, standalone_mock_app):
    standalone_mock_app.pending_transfer = {"sender": "Bob", "filename": "virus.exe"}
    standalone_mock_app.discovery.peers = {"Bob": {"ip": "1.1.1.1", "port": 1111}}
    standalone_mock_app.user_id = "Alice"

    cli.cmd_deny()
    
    assert standalone_mock_app.network.send_message.called
    assert cli.app.pending_transfer is None
    assert cli.app.awaiting_consent is False

def test_run_loop_exit(cli, standalone_mock_app):
    standalone_mock_app.shutdown = MagicMock()
    cli.commands["exit"]["func"] = standalone_mock_app.shutdown
    
    with patch("builtins.input", side_effect=["exit"]):
        with patch("builtins.print"):
            cli.run_loop()
    
    assert standalone_mock_app.shutdown.called
