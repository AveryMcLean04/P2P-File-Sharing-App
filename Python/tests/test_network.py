import pytest
import json
import base64
import socket
from unittest.mock import MagicMock, patch
from src.network.connection import NetworkManager
from src.network.dispatcher import MessageDispatcher
from src.network.discovery import MDNSHandler

# --- 1. Message Dispatcher Tests (Security & Routing) ---

def test_dispatcher_security_gate(mock_app):
    """Verify that private message types are blocked without a secure session."""
    logic = MagicMock()
    dispatcher = MessageDispatcher(mock_app, logic)
    
    # Message that REQUIRES a session
    private_msg = {"type": "CHAT_MESSAGE", "sender": "UnknownBob", "payload": "hi"}
    
    # Alice has no session with UnknownBob
    mock_app.active_sessions = {}
    
    dispatcher.handle(private_msg, ("1.2.3.4", 5000))
    
    # Assert: Logic was never triggered, security alert logged
    logic.process_chat_message.assert_not_called()
    mock_app.log.assert_called_with("security", pytest.approx("Blocked CHAT_MESSAGE"))

def test_dispatcher_routes_public_handshake(mock_app):
    """Verify that HANDSHAKE_INIT bypasses the security gate."""
    logic = MagicMock()
    dispatcher = MessageDispatcher(mock_app, logic)
    
    public_msg = {"type": "HANDSHAKE_INIT", "sender": "NewPeer", "payload": {}}
    
    dispatcher.handle(public_msg, ("1.2.3.4", 5000))
    
    # Assert: Logic was triggered even without a session
    logic.process_handshake_init.assert_called_once()

# --- 2. Network Manager Tests (TCP Communication) ---

@patch("socket.socket")
def test_network_manager_send_success(mock_socket_class, mock_app):
    """Verify NetworkManager correctly serializes JSON and sends over TCP."""
    mock_socket = MagicMock()
    mock_socket_class.return_value.__enter__.return_value = mock_socket
    
    nm = NetworkManager(mock_app, 5005, lambda m, a: None)
    test_payload = {"type": "PING", "sender": "Alice"}
    
    result = nm.send_message("192.168.1.10", 5005, test_payload)
    
    assert result is True
    mock_socket.connect.assert_called_with(("192.168.1.10", 5005))
    
    # Capture and verify the sent bytes
    sent_bytes = mock_socket.sendall.call_args[0][0]
    decoded_sent = json.loads(sent_bytes.decode('utf-8'))
    assert decoded_sent["type"] == "PING"

def test_broadcast_exit_logic(mock_app):
    """Verify that broadcast_peer_left iterates through all known peers."""
    nm = NetworkManager(mock_app, 5005, lambda m, a: None)
    nm.send_message = MagicMock() # Mock the actual send to avoid socket errors
    
    known_peers = {
        "Bob": {"ip": "1.1.1.1", "port": 5005},
        "Charlie": {"ip": "2.2.2.2", "port": 5005}
    }
    
    nm.broadcast_peer_left("Alice", known_peers)
    
    # Assert send_message was called twice
    assert nm.send_message.call_count == 2
    mock_app.log.assert_called_with("network", "Broadcasting exit to 2 peers...")

# --- 3. Discovery Tests (mDNS / Zeroconf) ---

def test_mdns_discovery_parsing(mock_app):
    """Verify that MDNSHandler correctly extracts peer info from Zeroconf properties."""
    handler = MDNSHandler(mock_app, "Alice", 5005)
    
    # Create a mock Zeroconf ServiceInfo object
    mock_info = MagicMock()
    # 127.0.0.1 in packed bytes
    mock_info.addresses = [socket.inet_aton("127.0.0.1")]
    mock_info.port = 5005
    mock_info.properties = {
        b"user_id": b"Bob",
        b"public_key": base64.b64encode(b"bob_pub_key")
    }
    
    mock_zc = MagicMock()
    mock_zc.get_service_info.return_value = mock_info
    
    # Trigger the callback
    handler.add_service(mock_zc, "_tcp.local.", "Bob._tcp.local.")
    
    # Verify Bob was added to the internal peer map
    assert "Bob" in handler.peers
    assert handler.peers["Bob"]["ip"] == "127.0.0.1"
    assert handler.peers["Bob"]["public_key"] == base64.b64encode(b"bob_pub_key").decode()

def test_mdns_discovery_ignores_self(mock_app):
    """Ensure the handler doesn't add the local user to the peer list."""
    handler = MDNSHandler(mock_app, "Alice", 5005) # Local ID is Alice
    
    mock_info = MagicMock()
    mock_info.properties = {b"user_id": b"Alice"} # Incoming ID is also Alice
    
    mock_zc = MagicMock()
    mock_zc.get_service_info.return_value = mock_info
    
    handler.add_service(mock_zc, "_tcp.local.", "Alice._tcp.local.")
    
    assert "Alice" not in handler.peers