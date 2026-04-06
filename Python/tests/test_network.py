import pytest
import json
import socket
from unittest.mock import MagicMock, patch, ANY
from src.network.connection import NetworkManager
from src.network.dispatcher import MessageDispatcher
from src.network.mdns_handler import MDNSHandler

@pytest.fixture
def mock_app():
    app = MagicMock()
    app.active_sessions = {}
    return app

# --- NetworkManager Tests ---

def test_network_send_message_success(mock_app):
    """Verify JSON serialization and socket connection for outgoing messages."""
    nm = NetworkManager(mock_app, 5000, MagicMock())
    
    with patch("socket.socket") as mock_socket:
        mock_conn = mock_socket.return_value.__enter__.return_value
        msg = {"type": "TEST", "payload": "hello"}
        
        result = nm.send_message("127.0.0.1", 5001, msg)
        
        assert result is True
        mock_conn.connect.assert_called_with(("127.0.0.1", 5001))
        sent_data = mock_conn.sendall.call_args[0][0]
        assert json.loads(sent_data.decode()) == msg

def test_network_receive_handle_client(mock_app):
    """Verify incoming socket data is reassembled and passed to callback."""
    callback = MagicMock()
    nm = NetworkManager(mock_app, 5000, callback)
    
    mock_conn = MagicMock()
    msg_dict = {"type": "CHAT", "sender": "Bob"}
    full_raw = json.dumps(msg_dict).encode()
    mock_conn.recv.side_effect = [full_raw[:5], full_raw[5:], b""]
    
    nm._handle_client(mock_conn, ("127.0.0.1", 12345))
    
    callback.assert_called_once_with(msg_dict, ("127.0.0.1", 12345))

# --- MessageDispatcher Tests ---

def test_dispatcher_security_gate(mock_app):
    """Verify dispatcher blocks non-public messages without a secure session."""
    logic = MagicMock()
    dispatcher = MessageDispatcher(mock_app, logic)
    
    msg = {"type": "FILE_LIST_REQUEST", "sender": "Stranger"}
    
    dispatcher.handle(msg, ("1.1.1.1", 5000))
    
    logic.handle_list_request.assert_not_called()
    mock_app.log.assert_any_call("security", ANY)

def test_dispatcher_routing_success(mock_app):
    """Verify dispatcher routes known types to the correct logic methods."""
    logic = MagicMock()
    dispatcher = MessageDispatcher(mock_app, logic)
    
    mock_app.active_sessions["Bob"] = {"status": "SECURE-SESSION"}
    
    msg = {"type": "CHAT_MESSAGE", "sender": "Bob", "payload": {"text": "hi"}}
    dispatcher.handle(msg, ("1.1.1.1", 5000))
    
    logic.process_chat_message.assert_called_once_with("Bob", {"text": "hi"})

# --- MDNSHandler Tests ---

def test_mdns_get_local_ip(mock_app):
    """Verify IP discovery logic returns a string IP."""
    handler = MDNSHandler(mock_app, "Alice", 5000)
    
    with patch("socket.socket") as mock_s:
        mock_s.return_value.getsockname.return_value = ["192.168.1.50"]
        ip = handler._get_local_ip()
        assert ip == "192.168.1.50"

def test_mdns_add_service_discovery(mock_app):
    """Verify that discovering a service updates the internal peer list."""
    handler = MDNSHandler(mock_app, "Alice", 5000)
    mock_zc = MagicMock()
    
    info = MagicMock()
    info.addresses = [socket.inet_aton("192.168.1.100")]
    info.port = 6000
    info.properties = {b"user_id": b"Bob", b"public_key": b"base64key"}
    
    mock_zc.get_service_info.return_value = info
    
    handler.add_service(mock_zc, "_tcp.local.", "Bob._tcp.local.")
    
    assert "Bob" in handler.peers
    assert handler.peers["Bob"]["ip"] == "192.168.1.100"
    assert handler.peers["Bob"]["port"] == 6000

def test_mdns_remove_service(mock_app):
    """Verify that removing a service cleans up the peer list."""
    handler = MDNSHandler(mock_app, "Alice", 5000)
    handler.peers["Bob"] = {"ip": "1.2.3.4"}
    
    handler.remove_service(MagicMock(), "_tcp.local.", "Bob._tcp.local.")
    
    assert "Bob" not in handler.peers
    mock_app.log.assert_any_call("network", "Peer Offline: Bob")

# --- Shutdown Tests ---

def test_stop_signal_propagation(mock_app):
    """Ensure stop methods set running flags and close resources."""
    nm = NetworkManager(mock_app, 5000, MagicMock())
    nm.stop()
    assert nm.running is False
    
    import pytest
import json
import socket
from unittest.mock import MagicMock, patch, ANY
from src.network.connection import NetworkManager
from src.network.dispatcher import MessageDispatcher
from src.network.mdns_handler import MDNSHandler

@pytest.fixture
def mock_app():
    app = MagicMock()
    app.active_sessions = {}
    return app

# --- NetworkManager Tests ---

def test_network_send_message_success(mock_app):
    """Verify JSON serialization and socket connection for outgoing messages."""
    nm = NetworkManager(mock_app, 5000, MagicMock())
    
    with patch("socket.socket") as mock_socket:
        mock_conn = mock_socket.return_value.__enter__.return_value
        msg = {"type": "TEST", "payload": "hello"}
        
        result = nm.send_message("127.0.0.1", 5001, msg)
        
        assert result is True
        mock_conn.connect.assert_called_with(("127.0.0.1", 5001))
        sent_data = mock_conn.sendall.call_args[0][0]
        assert json.loads(sent_data.decode()) == msg

def test_network_receive_handle_client(mock_app):
    """Verify incoming socket data is reassembled and passed to callback."""
    callback = MagicMock()
    nm = NetworkManager(mock_app, 5000, callback)
    
    mock_conn = MagicMock()
    msg_dict = {"type": "CHAT", "sender": "Bob"}
    full_raw = json.dumps(msg_dict).encode()
    mock_conn.recv.side_effect = [full_raw[:5], full_raw[5:], b""]
    
    nm._handle_client(mock_conn, ("127.0.0.1", 12345))
    
    callback.assert_called_once_with(msg_dict, ("127.0.0.1", 12345))

# --- MessageDispatcher Tests ---

def test_dispatcher_security_gate(mock_app):
    """Verify dispatcher blocks non-public messages without a secure session."""
    logic = MagicMock()
    dispatcher = MessageDispatcher(mock_app, logic)
    
    msg = {"type": "FILE_LIST_REQUEST", "sender": "Stranger"}
    
    dispatcher.handle(msg, ("1.1.1.1", 5000))
    
    logic.handle_list_request.assert_not_called()
    mock_app.log.assert_any_call("security", ANY)

def test_dispatcher_routing_success(mock_app):
    """Verify dispatcher routes known types to the correct logic methods."""
    logic = MagicMock()
    dispatcher = MessageDispatcher(mock_app, logic)
    
    mock_app.active_sessions["Bob"] = {"status": "SECURE-SESSION"}
    
    msg = {"type": "CHAT_MESSAGE", "sender": "Bob", "payload": {"text": "hi"}}
    dispatcher.handle(msg, ("1.1.1.1", 5000))
    
    logic.process_chat_message.assert_called_once_with("Bob", {"text": "hi"})

# --- MDNSHandler Tests ---

def test_mdns_get_local_ip(mock_app):
    """Verify IP discovery logic returns a string IP."""
    handler = MDNSHandler(mock_app, "Alice", 5000)
    
    with patch("socket.socket") as mock_s:
        mock_s.return_value.getsockname.return_value = ["192.168.1.50"]
        ip = handler._get_local_ip()
        assert ip == "192.168.1.50"

def test_mdns_add_service_discovery(mock_app):
    """Verify that discovering a service updates the internal peer list."""
    handler = MDNSHandler(mock_app, "Alice", 5000)
    mock_zc = MagicMock()
    
    info = MagicMock()
    info.addresses = [socket.inet_aton("192.168.1.100")]
    info.port = 6000
    info.properties = {b"user_id": b"Bob", b"public_key": b"base64key"}
    
    mock_zc.get_service_info.return_value = info
    
    handler.add_service(mock_zc, "_tcp.local.", "Bob._tcp.local.")
    
    assert "Bob" in handler.peers
    assert handler.peers["Bob"]["ip"] == "192.168.1.100"
    assert handler.peers["Bob"]["port"] == 6000

def test_mdns_remove_service(mock_app):
    """Verify that removing a service cleans up the peer list."""
    handler = MDNSHandler(mock_app, "Alice", 5000)
    handler.peers["Bob"] = {"ip": "1.2.3.4"}
    
    handler.remove_service(MagicMock(), "_tcp.local.", "Bob._tcp.local.")
    
    assert "Bob" not in handler.peers
    mock_app.log.assert_any_call("network", "Peer Offline: Bob")

# --- Shutdown Tests ---

def test_stop_signal_propagation(mock_app):
    """Ensure stop methods set running flags and close resources."""
    nm = NetworkManager(mock_app, 5000, MagicMock())
    nm.stop()
    assert nm.running is False
    
    with patch("src.network.mdns_handler.Zeroconf") as MockZC:
        handler = MDNSHandler(mock_app, "Alice", 5000)
        
        handler.browser = MagicMock()
        handler.stop()
        
        MockZC.return_value.close.assert_called()
        handler.browser.cancel.assert_called()