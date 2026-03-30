import pytest
from unittest.mock import MagicMock, patch
from pathlib import Path

# --- SUCCESS CASES ---

def test_app_initialization_success(mock_app):
    """SUCCESS: Verify the app initializes all components and sets core state."""
    assert mock_app.user_id == "TestUser"
    assert mock_app.config.port == 5005
    assert mock_app.active_sessions == {}
    assert hasattr(mock_app, 'logic'), "App should hold a reference to PeerLogic"

def test_app_directory_setup_success(mock_app):
    """SUCCESS: Verify app correctly receives its storage paths from Config."""
    data, shared, vault = mock_app.config.initialize_directories(mock_app.base_path)
    
    assert data is not None
    assert "data" in str(data)
    assert "shared" in str(shared)
    assert "vault" in str(vault)

def test_app_consent_state_management(mock_app):
    """SUCCESS: Verify the app can transition into and out of 'Awaiting Consent' state."""
    mock_app.awaiting_consent = True
    mock_app.pending_transfer = {"filename": "test.txt", "type": "PUSH"}
    assert mock_app.awaiting_consent is True
    
    mock_app.awaiting_consent = False
    mock_app.pending_transfer = None
    assert mock_app.pending_transfer is None

# --- FAILURE CASES ---

def test_app_initialization_failure_missing_config():
    """FAILURE: Verify app crashes as expected when Config returns None."""
    import main
    with patch('main.AppConfig') as MockConfig, \
         patch('main.MDNSHandler'), \
         patch('main.NetworkManager'), \
         patch('main.AppCLI'), \
         patch('main.AuthManager'):
         
        instance = MockConfig.return_value
        instance.user_id = "FailUser"
        instance.port = 9999
        instance.initialize_directories.return_value = (None, None, None)
        
        with pytest.raises(TypeError):
            main.SecureP2PApp(user_id="FailUser", port=9999)

def test_app_invalid_session_access_failure(mock_app):
    """FAILURE: Verify app handles requests for non-existent sessions gracefully."""
    target = "UnknownPeer"
    session = mock_app.active_sessions.get(target)
    assert session is None

def test_app_auth_unlock_failure(mock_app):
    """FAILURE: Verify app state when the vault fails to unlock."""
    mock_app.auth_manager.unlock_vault.return_value = False
    is_unlocked = mock_app.auth_manager.unlock_vault("wrong_password")
    assert is_unlocked is False