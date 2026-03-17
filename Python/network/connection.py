import socket
import threading
import json

class NetworkManager:
    def __init__(self, port, message_callback):
        self.port = port
        self.message_callback = message_callback
        self.running = True
        self.server_thread = None

    def start_server(self):
        """Requirement 3: Start the background TCP listener."""
        self.server_thread = threading.Thread(target=self._listen_loop, daemon=True)
        self.server_thread.start()
        print(f"[*] Network Listener started on port {self.port}")

    def _listen_loop(self):
        """The actual socket listening loop."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('0.0.0.0', self.port))
            s.listen()
            
            while self.running:
                try:
                    # Set a timeout so we can check if self.running is still True
                    s.settimeout(1.0) 
                    conn, addr = s.accept()
                    client_thread = threading.Thread(
                        target=self._handle_client, 
                        args=(conn, addr)
                    )
                    client_thread.start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        print(f"[!] Server error: {e}")

    def _handle_client(self, conn, addr):
        """Processes incoming JSON data."""
        with conn:
            try:
                data = conn.recv(65536).decode('utf-8') # Increased buffer for files
                if data:
                    message = json.loads(data)
                    # Pass the message back to SecureP2PApp.handle_incoming_message
                    self.message_callback(message, addr)
            except Exception as e:
                print(f"[!] Error handling client {addr}: {e}")

    def send_message(self, ip, port, message_dict):
        """Sends a JSON message to a peer."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5.0)
                s.connect((ip, port))
                s.sendall(json.dumps(message_dict).encode('utf-8'))
        except Exception as e:
            print(f"[!] Failed to send message to {ip}:{port} -> {e}")

    def stop(self):
        """Shuts down the listener."""
        self.running = False
        if self.server_thread:
            self.server_thread.join(timeout=2.0)