import pytest
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

project_root = str(Path(__file__).resolve().parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

@pytest.fixture
def mock_app(tmp_path):
    """
    Creates a mocked version of the SecureP2PApp with all major subsystems 
    replaced by MagicMocks to isolate logic, storage, and CLI tests.
    """
    data_dir = tmp_path / "data"
    shared_dir = tmp_path / "shared"
    vault_dir = tmp_path / "vault"
    
    import main

    with patch('network.mdns_handler.MDNSHandler'), \
         patch('network.connection.NetworkManager'), \
         patch('ui.cli.AppCLI'), \
         patch('config.AppConfig') as MockConfig, \
         patch('authentication.auth_manager.AuthManager') as MockAuth, \
         patch('logic.peer_logic.PeerLogic') as MockLogic, \
         patch('crypto.secure_disk_store.SecureDiskStore') as MockDisk:
        
        instance_config = MockConfig.return_value
        instance_config.user_id = "TestUser"
        instance_config.port = 5005
        instance_config.initialize_directories.return_value = (data_dir, shared_dir, vault_dir)
        
        app = main.SecureP2PApp(user_id="TestUser", port=5005)
        app.log = MagicMock()
        
        app.auth_manager = MockAuth.return_value
        app.auth_manager.get_public_key.return_value = b"A" * 32
        app.auth_manager.unlock_vault.return_value = True
        app.auth_manager.pending_handshakes = {}
        
        app.logic = MockLogic.return_value
        
        app.disk_store = MockDisk.return_value
        app.disk_store.list_encrypted_files.return_value = []
        
        app.awaiting_consent = False
        app.pending_transfer = None
        app.network = MagicMock()
        app.discovery = MagicMock()
        app.discovery.peers = {}
        app.active_sessions = {}
        
        yield app

@pytest.fixture
def secure_session(mock_app):
    """
    Helper fixture that sets up a mock 'Bob' who has already completed 
    a handshake, allowing for testing of encrypted chat and file transfers.
    """
    sender = "Bob"
    mock_encryptor = MagicMock()
    
    mock_encryptor.encrypt.side_effect = lambda x: b"enc_" + (x.encode() if isinstance(x, str) else x)
    mock_encryptor.decrypt.side_effect = lambda x: x.replace(b"enc_", b"")
    
    mock_app.active_sessions[sender] = {
        "status": "SECURE-SESSION",
        "encryptor": mock_encryptor,
        "peer_identity": b"B" * 32
    }
    
    return mock_app, sender