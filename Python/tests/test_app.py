import pytest
from unittest.mock import patch, MagicMock

# --- Login Tests ---

def test_login_success(mock_app):
    """Test that valid credentials trigger post-login initialization."""
    mock_app.disk_store = None 
    
    with patch("getpass.getpass", return_value="correct_password"):
        mock_app.config.password = "correct_password"
        
        result = mock_app.login()
        
        assert result is True
        mock_app.auth_manager.unlock_vault.assert_called_once_with("correct_password")

        assert mock_app.discovery.start_discovery.called

def test_login_failure(mock_app):
    """Test that incorrect credentials prevent app initialization."""
    with patch("getpass.getpass", return_value="wrong_password"):
        mock_app.config.password = "correct_password"
        
        result = mock_app.login(max_retries=1)
        
        assert result is False
        mock_app.discovery.start_discovery.assert_not_called()

# --- Lifecycle Tests ---

def test_run_starts_services(mock_app):
    """Verify that run() kicks off the network server and CLI."""
    with patch.object(mock_app.cli, 'run_loop') as mock_loop:
        mock_app.run()
        
        mock_app.network.start_server.assert_called_once()
        mock_loop.assert_called_once()

def test_shutdown_cleanup(mock_app):
    """Verify that shutdown notifies peers and stops network services."""
    with patch("os._exit"):
        mock_app.shutdown()
        
        mock_app.network.broadcast_peer_left.assert_called_once()
        mock_app.discovery.stop.assert_called_once()
        mock_app.network.stop.assert_called_once()

# --- Initialization Logic ---

def test_post_login_init_failure(mock_app):
    """Test behavior when the identity key is missing during boot."""
    mock_app.disk_store = None
    mock_app.auth_manager.get_public_key.return_value = None
    
    with patch.object(mock_app, 'shutdown') as mock_shutdown:
        mock_app.post_login_init()
        mock_shutdown.assert_called_once()