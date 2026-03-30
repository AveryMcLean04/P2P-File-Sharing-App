import pytest
import socket
import json
import base64
from unittest.mock import MagicMock, patch, ANY

from network.connection import NetworkManager
from network.dispatcher import MessageDispatcher
from network.mdns_handler import MDNSHandler

# --- 1. NetworkManager Tests ---

def test_nm_send_message_success(mock_app):
    nm = NetworkManager(mock_app, port=5005, message_callback=lambda m, a: None)
    payload = {"type": "HELLO"}
    with patch('socket.socket') as mock_socket:
        mock_conn = mock_socket.return_value.__enter__.return_value
        success = nm.send_message("127.0.0.1", 5005, payload)
        assert success is True
        mock_conn.sendall.assert_called_once()

def test_nm_send_message_connection_failure(mock_app):
    nm = NetworkManager(mock_app, port=5005, message_callback=lambda m, a: None)
    with patch('socket.socket') as mock_socket:
        mock_socket.return_value.__enter__.return_value.connect.side_effect = Exception("No route")
        success = nm.send_message("1.1.1.1", 5005, {"type": "PING"})
        assert success is False
        mock_app.log.assert_called_with("error", ANY)

def test_nm_receive_malformed_json_failure(mock_app):
    nm = NetworkManager(mock_app, port=5005, message_callback=lambda m, a: None)
    mock_conn = MagicMock()
    mock_conn.recv.side_effect = [b"\xff\xfe\xfd", b""]
    nm._handle_client(mock_conn, ("1.2.3.4", 9999))
    mock_app.log.assert_any_call("error", ANY)

# --- 2. MessageDispatcher Tests ---

def test_dispatcher_secure_route_success(mock_app):
    logic = MagicMock()
    dispatcher = MessageDispatcher(mock_app, logic)
    mock_app.active_sessions["Bob"] = {"status": "SECURE-SESSION"}
    msg = {"type": "CHAT_MESSAGE", "sender": "Bob", "payload": "hello"}
    dispatcher.handle(msg, ("1.1.1.1", 5000))
    logic.process_chat_message.assert_called_once()

def test_dispatcher_security_gate_failure(mock_app):
    logic = MagicMock()
    dispatcher = MessageDispatcher(mock_app, logic)
    mock_app.active_sessions = {} 
    msg = {"type": "FILE_LIST_REQUEST", "sender": "Attacker"}
    dispatcher.handle(msg, ("6.6.6.6", 6666))
    logic.handle_list_request.assert_not_called()
    mock_app.log.assert_called_with("security", ANY)

def test_dispatcher_unknown_type_failure(mock_app):
    dispatcher = MessageDispatcher(mock_app, MagicMock())
    sender_name = "Alice"
    mock_app.active_sessions[sender_name] = {"status": "SECURE-SESSION"}
    msg = {"type": "GHOST_TYPE", "sender": sender_name}
    dispatcher.handle(msg, ("1.1.1.1", 5000))
    mock_app.log.assert_called_with("network", ANY)

# --- 3. MDNSHandler Tests ---

def test_mdns_discovery_success(mock_app):
    mdns = MDNSHandler(mock_app, user_id="Alice", port=5000)
    mock_info = MagicMock()
    mock_info.addresses = [socket.inet_aton("192.168.1.50")]
    mock_info.port = 5001
    mock_info.properties = {b"user_id": b"Bob", b"public_key": b"abc"}
    mock_zc = MagicMock()
    mock_zc.get_service_info.return_value = mock_info
    mdns.add_service(mock_zc, "type", "Bob.type")
    assert "Bob" in mdns.peers

def test_mdns_registration_failure(mock_app):
    """
    
    """
    mdns = MDNSHandler(mock_app, user_id="Alice", port=5000)
    
    mock_zc_instance = MagicMock()
    mock_zc_instance.register_service.side_effect = Exception("Bind error")
    
    mdns.zeroconf = mock_zc_instance
    
    with patch('network.mdns_handler.ServiceInfo'):
        mdns.register_service()
        
    mock_app.log.assert_called_with("error", ANY)

def test_mdns_remove_service(mock_app):
    """Verifies that remove_service correctly cleans up the peer list."""
    mdns = MDNSHandler(mock_app, user_id="Alice", port=5000)
    mdns.peers["Bob"] = {"ip": "1.1.1.1", "port": 5000}
    
    mdns.remove_service(MagicMock(), "type", "Bob.type")
    
    assert "Bob" not in mdns.peers
    mock_app.log.assert_called_with("network", ANY)