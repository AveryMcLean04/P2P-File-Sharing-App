import sys
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

# --- Path Configuration ---
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

@pytest.fixture
def mock_app(tmp_path):
    """
    Creates a mocked version of SecureP2PApp with all major subsystems 
    replaced by MagicMocks to isolate logic, storage, and CLI tests.
    """
    data_dir = tmp_path / "data"
    shared_dir = tmp_path / "shared"
    vault_dir = tmp_path / "vault"
    
    import main

    # Use a context manager to patch dependencies before instantiation
    with patch('src.network.mdns_handler.MDNSHandler'), \
         patch('src.network.connection.NetworkManager'), \
         patch('src.ui.cli.AppCLI'), \
         patch('src.config.AppConfig') as mock_config_cls, \
         patch('src.authentication.auth_manager.AuthManager') as mock_auth_cls, \
         patch('src.logic.peer_logic.PeerLogic') as mock_logic_cls, \
         patch('src.crypto.secure_disk_store.SecureDiskStore') as mock_disk_cls:
        
        # Configure Config Mock
        instance_config = mock_config_cls.return_value
        instance_config.user_id = "TestUser"
        instance_config.port = 5005
        instance_config.initialize_directories.return_value = (data_dir, shared_dir, vault_dir)
        
        # Instantiate App
        app = main.SecureP2PApp(user_id="TestUser", port=5005)
        
        # Inject Mocked Managers
        app.log = MagicMock()
        app.auth_manager = mock_auth_cls.return_value
        app.logic = mock_logic_cls.return_value
        app.disk_store = mock_disk_cls.return_value
        app.network = MagicMock()
        app.discovery = MagicMock()
        
        # Set Default Mock Behaviors
        app.auth_manager.get_public_key.return_value = b"A" * 32
        app.auth_manager.unlock_vault.return_value = True
        app.auth_manager.pending_handshakes = {}
        app.disk_store.list_encrypted_files.return_value = []
        
        # Initialize State
        app.awaiting_consent = False
        app.pending_transfer = None
        app.discovery.peers = {}
        app.active_sessions = {}
        
        yield app

@pytest.fixture
def secure_session(mock_app):
    """
    Helper fixture: Sets up a mock peer 'Bob' with an active secure session.
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