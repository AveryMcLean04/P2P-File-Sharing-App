import socket
import threading
import json

class NetworkManager:
    def __init__(self, app, port, message_callback):
        self.app = app
        self.port = port
        self.message_callback = message_callback
        self.running = True
        self.server_thread = None

    def start_server(self):
        self.server_thread = threading.Thread(target=self._listen_loop, daemon=True)
        self.server_thread.start()
        self.app.log("system", f"Network Listener started on port {self.port}")

    def _listen_loop(self):
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

    def _handle_client(self, conn, addr):
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
            except Exception as e:
                self.app.log("error", f"Error handling client {addr}: {e}")

    def send_message(self, ip, port, message_dict):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(10.0)
                s.connect((ip, port))
                s.sendall(json.dumps(message_dict).encode('utf-8'))
                return True
        except Exception as e:
            self.app.log("system", f"Failed to send message to {ip}:{port}")
            return False

    def broadcast_peer_left(self, sender_id, peers):
        message = {
            "type": "PEER_LEFT",
            "sender": sender_id,
            "payload": {}
        }

        for peer_id, peer_info in peers.items():
            ip = peer_info.get("ip")
            port = peer_info.get("port")
            if ip and port:
                self.send_message(ip, port, message)

    def stop(self):
        self.running = False