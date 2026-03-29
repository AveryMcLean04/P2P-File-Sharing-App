import socket
import threading
import json
from typing import Dict, Any, Callable

class NetworkManager:
    """
    Handles the underlying TCP networking for the application.
    Responsible for maintaining a listener server for incoming messages
    and providing methods for targeted and broadcast outgoing communication.
    """
    
    def __init__(self, app, port: int, message_callback: Callable[[Dict, tuple], None]):
        """
        Initializes the network manager.
        
        :param app: The main SecureP2PApp instance.
        :param port: The local port to bind the listener server.
        :param message_callback: A function to process received JSON messages.
        """
        self.app = app
        self.port = port
        self.message_callback = message_callback
        self.running = True
        self.server_thread = None

    def start_server(self) -> None:
        """
        Starts the background listening thread to accept incoming P2P connections.
        """
        self.server_thread = threading.Thread(target=self._listen_loop, daemon=True)
        self.server_thread.start()
        self.app.log("network", f"Listener started on port {self.port}")

    def _listen_loop(self):
        """
        Main server loop that binds to the port and spawns handler threads 
        for each incoming connection.
        """
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
        """
        Receives data from a peer, reassembles chunks, and parses the JSON payload.
        """
        with conn:
            try:
                chunks = []
                while True:
                    chunk = conn.recv(1024 * 1024)
                    if not chunk:
                        break
                    chunks.append(chunk)

                if chunks:
                    full_data = b"".join(chunks).decode('utf-8')
                    message = json.loads(full_data)
                    self.message_callback(message, addr)
            except json.JSONDecodeError:
                self.app.log("error", f"Received malformed JSON from {addr}")
            except Exception as e:
                self.app.log("error", f"Error handling client {addr}: {e}")

    def send_message(self, ip: str, port: int, message_dict_or_str: Any) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(10.0)
                s.connect((ip, port))
                
                # If it's already a string, just encode it. If it's a dict, use json.dumps.
                if isinstance(message_dict_or_str, str):
                    data = message_dict_or_str.encode('utf-8')
                else:
                    data = json.dumps(message_dict_or_str).encode('utf-8')
                    
                s.sendall(data)
                return True
        except Exception:
            return False

    def broadcast_peer_left(self, sender_id: str, peers: Dict[str, Dict]):
        """
        Notifies all known peers that this user is disconnecting from the network.
        
        :param sender_id: Our local User ID.
        :param peers: The dictionary of active peers from MDNSHandler.
        """
        message = {
            "type": "PEER_LEFT",
            "sender": sender_id,
            "payload": {}
        }

        self.app.log("network", f"Broadcasting exit to {len(peers)} peers...")
        for peer_id, peer_info in peers.items():
            ip = peer_info.get("ip")
            port = peer_info.get("port")
            if ip and port:
                self.send_message(ip, port, message)

    def stop(self) -> None:
        """
        Signals the server loop to stop and prepares for application shutdown.
        """
        self.running = False
        self.app.log("network", "Network manager shutting down.")