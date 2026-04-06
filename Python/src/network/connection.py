import socket
import threading
import json
from typing import Dict, Any, Callable

class NetworkManager:
    """
    Handles TCP networking, including the listener server and outgoing messages.
    """
    def __init__(self, app, port: int, message_callback: Callable[[Dict, tuple], None]):
        self.app = app
        self.port = port
        self.message_callback = message_callback
        self.running = True
        self.server_thread = None

    def start_server(self) -> None:
        """Starts the background thread to listen for incoming P2P connections."""
        self.server_thread = threading.Thread(target=self._listen_loop, daemon=True)
        self.server_thread.start()
        self.app.log("network", f"Listener started on port {self.port}")

    def _listen_loop(self):
        """Main server loop for binding the port and accepting connections."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(('0.0.0.0', self.port))
            except Exception as e:
                self.app.log("error", f"Bind failed: {e}")
                return
            
            s.listen(5)
            s.settimeout(1.0)

            while self.running:
                try:
                    conn, addr = s.accept()
                    threading.Thread(target=self._handle_client, args=(conn, addr), daemon=True).start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        self.app.log("error", f"Server error: {e}")

    def _handle_client(self, conn: socket.socket, addr: tuple):
        """Reassembles incoming data chunks and parses the JSON payload."""
        with conn:
            try:
                chunks = []
                while True:
                    chunk = conn.recv(1024 * 1024)
                    if not chunk: break
                    chunks.append(chunk)

                if chunks:
                    full_data = b"".join(chunks).decode('utf-8')
                    message = json.loads(full_data)
                    self.message_callback(message, addr)
            except json.JSONDecodeError:
                self.app.log("error", f"Malformed JSON from {addr}")
            except Exception as e:
                self.app.log("error", f"Error handling client {addr}: {e}")

    def send_message(self, ip: str, port: int, message_dict_or_str: Any) -> bool:
        """Sends a JSON-encoded message to a specific peer."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(10.0)
                s.connect((ip, port))
                
                if isinstance(message_dict_or_str, str):
                    data = message_dict_or_str.encode('utf-8')
                else:
                    data = json.dumps(message_dict_or_str).encode('utf-8')
                    
                s.sendall(data)
                return True
        except Exception:
            # Silently failing to avoid log spam during broad network sweeps
            return False

    def broadcast_peer_left(self, sender_id: str, peers: Dict[str, Dict]):
        """Notifies all active peers that this node is disconnecting."""
        message = {
            "type": "PEER_LEFT",
            "sender": sender_id,
            "payload": {}
        }

        self.app.log("network", f"Broadcasting exit to {len(peers)} peers.")
        for peer_id, peer_info in peers.items():
            ip, port = peer_info.get("ip"), peer_info.get("port")
            if ip and port:
                self.send_message(ip, port, message)

    def stop(self) -> None:
        """Signals the listener loop to terminate."""
        self.running = False
        self.app.log("network", "Network manager stopping.")