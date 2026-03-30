import pytest
from unittest.mock import patch, MagicMock

def test_app_initialization(mock_app):
    assert mock_app.user_id == "TestUser"
    mock_app.config.initialize_directories.assert_called_once()

def test_chat_decryption(secure_session, capsys):
    app, peer_name = secure_session
    app.logic.process_chat_message(peer_name, "ZW5jX0hlbGxv")
    
    captured = capsys.readouterr()
    assert "Hello" in captured.out

## --- Test Cases ---

def test_app_initialization(mock_app):
    """Check if directories and managers are set up correctly."""
    assert mock_app.user_id == "TestUser"
    assert mock_app.disk_store is None
    mock_app.config.initialize_directories.assert_called_once()

@patch('getpass.getpass')
def test_login_success(mock_getpass, mock_app):
    """Test successful login and transition to post_login_init."""
    mock_getpass.return_value = "password123"
    mock_app.auth_manager.unlock_vault.return_value = True
    
    with patch('main.SecureDiskStore'):
        result = mock_app.login()
        
    assert result is True
    assert mock_app.auth_manager.unlock_vault.called
    mock_app.discovery.register_service.assert_called()

@patch('getpass.getpass')
def test_login_failure(mock_getpass, mock_app):
    """Test that login fails after incorrect password attempts."""
    mock_getpass.return_value = "wrong_password"
    
    result = mock_app.login(max_retries=2)
    
    assert result is False
    assert mock_app.disk_store is None

def test_shutdown_sequence(mock_app):
    """Ensure all networking services are stopped on shutdown."""
    with patch('os._exit'):
        mock_app.shutdown()
        
    mock_app.network.broadcast_peer_left.assert_called_once()
    mock_app.discovery.stop.assert_called_once()
    mock_app.network.stop.assert_called_once()

def test_logging_output(mock_app, capsys):
    """Verify the log method prints to stdout correctly."""
    mock_app.log("network", "Scanning for peers...")
    captured = capsys.readouterr()
    assert "[NETWORK] Scanning for peers..." in captured.out