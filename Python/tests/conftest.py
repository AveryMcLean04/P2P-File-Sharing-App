import pytest
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

@pytest.fixture
def mock_app(tmp_path):
    """
    Sets up a fully mocked SecureP2PApp instance.
    Uses a temporary directory for all filesystem operations.
    """
    user_id = "TestUser"
    port = 5005
    
    # Path setup for the mock app
    data_dir = tmp_path / "data"
    shared_dir = tmp_path / "shared"
    vault_dir = tmp_path / "vault"
    
    # We patch the components in 'main' (or wherever SecureP2PApp is defined)
    # so that initialization doesn't trigger real network/disk activity.
    with patch('main.MDNSHandler'), \
         patch('main.NetworkManager'), \
         patch('main.AppConfig') as MockConfig, \
         patch('main.AuthManager') as MockAuth:
        
        # 1. Setup Mock Config
        instance_config = MockConfig.return_value
        instance_config.user_id = user_id
        instance_config.port = port
        instance_config.password = "password123"
        instance_config.initialize_directories.return_value = (
            data_dir, shared_dir, vault_dir
        )
        
        # 2. Import and Initialize App
        from main import SecureP2PApp
        app = SecureP2PApp(user_id=user_id, port=port)
        
        # 3. Setup Mock AuthManager
        app.auth_manager = MockAuth.return_value
        
        app.auth_manager.generate_ephemeral_pair.return_value = (b"fake_priv", b"fake_pub")
        
        app.auth_manager.sign.return_value = b"fake_signature"
        app.auth_manager.get_public_key.return_value = b"A" * 32
        
        app.auth_manager.local_encryptor = MagicMock()
        app.auth_manager.local_encryptor.encrypt.return_value = b"encrypted_data"
        app.auth_manager.local_encryptor.decrypt.return_value = b"decrypted_data"
        app.auth_manager.pending_handshakes = {}
        
        # 4. Setup Mock Network/Discovery
        app.network = MagicMock()
        app.discovery = MagicMock()
        app.discovery.peers = {}
        
        # 5. Additional State needed for Logic tests
        app.active_sessions = {}
        app.awaiting_consent = False
        app.pending_transfer = None
        
        yield app

@pytest.fixture
def secure_session(mock_app):
    """
    A helper fixture that injects a pre-established 
    secure session with a peer named 'Bob'.
    """
    sender = "Bob"
    mock_encryptor = MagicMock()
    
    # Define standard behavior for the session encryptor
    mock_encryptor.encrypt.side_effect = lambda x: b"enc_" + x
    mock_encryptor.decrypt.side_effect = lambda x: x.replace(b"enc_", b"")
    
    mock_app.active_sessions[sender] = {
        "status": "SECURE-SESSION",
        "encryptor": mock_encryptor,
        "peer_identity": b"B" * 32
    }
    return mock_app, sender