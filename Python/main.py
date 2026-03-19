import os
import sys
import time
import base64
from pathlib import Path
from dataclasses import dataclass

# Path setup and imports
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))
try:
    from discovery.mdns_handler import MDNSHandler
    from crypto.key_manager import KeyManager
    from crypto.session import SessionManager
    from crypto.encryption import FileEncryptor
    from crypto.storage import SecureStorage
    from network.connection import NetworkManager
except ImportError as e:
    print(f"[-] Critical Error: Missing internal modules. {e}")
    sys.exit(1)

@dataclass
class AppConfig:
    user_id: str = "Alice_Python"
    port: int = 5000
    service_type: str = "_cisc468secshare._tcp.local."
    shared_dir_name: str = "shared_test_files"
    
    @property
    def data_dir_name(self) -> str:
        return f"data_{self.user_id}"

class SecureP2PApp:
    def __init__(self, user_id="Alice_Python", port=5000):
        self.config = AppConfig(user_id=user_id, port=port)
        self.base_path = Path(__file__).resolve().parent
        self.active_sessions = {}

        # Path definitions
        self.data_path = self.base_path / self.config.data_dir_name
        self.shared_path = self.base_path / self.config.shared_dir_name
        self._setup_directories()

        # Module Initialization
        self.key_mgr = KeyManager(keys_dir=str(self.data_path / "keys"))
        self.key_mgr.load_or_generate_keys()
        
        self.storage = SecureStorage(password="my_secure_password_123")
        self.network = NetworkManager(self.config.port, self.handle_incoming_message)
        self.discovery = MDNSHandler(self.config.user_id, self.config.port, self.config.service_type)

        # CLI Command Mapping
        self.commands = {
            "help":    {"func": self._cmd_help,    "desc": "Show all available commands"},
            "list":    {"func": self._cmd_list,    "desc": "List discovered network peers"},
            "connect": {"func": self._cmd_connect, "desc": "Establish a secure session with a peer"},
            "fetch":   {"func": self._cmd_fetch,   "desc": "Request file list from a connected peer"},
            "send":    {"func": self._cmd_send,    "desc": "Send an encrypted file to a peer"},
            "rotate":  {"func": self._cmd_rotate,  "desc": "Rotate your identity keys (PFS)"},
            "exit":    {"func": self._cmd_exit,    "desc": "Safely shut down the application"}
        }

    def _setup_directories(self):
        """Creates necessary folder structure using pathlib."""
        (self.data_path / "encrypted").mkdir(parents=True, exist_ok=True)
        (self.data_path / "keys").mkdir(parents=True, exist_ok=True)
        (self.data_path / "received").mkdir(parents=True, exist_ok=True)
        self.shared_path.mkdir(parents=True, exist_ok=True)

    def log(self, category, message):
        timestamp = time.strftime('%H:%M:%S')
        print(f"[{timestamp}] [{category.upper():^10}] {message}")

    # --- NETWORK DISPATCHER ---

    def handle_incoming_message(self, message, addr):
        """Routes incoming dictionary messages to the correct logic."""
        m_type = message.get("type")
        sender = message.get("sender")
        payload = message.get("payload")

        if m_type == "HANDSHAKE_INIT":
            self._process_handshake_init(sender, payload, addr)
        elif m_type == "HANDSHAKE_RESPONSE":
            self._process_handshake_response(sender, payload)
        elif m_type == "FILE_TRANSFER":
            self._process_file_transfer(sender, payload)
        elif m_type == "FILE_LIST_REQUEST":
            self._handle_list_request(sender)
        else:
            self.log("network", f"Unknown message type from {sender}: {m_type}")

    # --- CLI COMMAND METHODS ---

    def _cmd_help(self, *args):
        print(f"\n{'COMMAND':<12} | {'DESCRIPTION'}")
        print("-" * 45)
        for cmd, info in self.commands.items():
            print(f"{cmd:<12} | {info['desc']}")

    def _cmd_list(self, *args):
        peers = self.discovery.get_active_peers()
        if not peers:
            return print("[-] No peers discovered on the network.")
        
        for name, info in peers.items():
            status = "Secured" if name in self.active_sessions and "encryptor" in self.active_sessions[name] else "?? Open"
            print(f" > {name:<15} [{info['address']}:{info['port']}] {status}")

    def _cmd_connect(self, *args):
        target = input("Connect to peer ID: ")
        peers = self.discovery.get_active_peers()
        
        if target not in peers:
            return print(f"[-] Peer '{target}' not found.")

        session = SessionManager()
        # Keep track of the pending session to finalize once response arrives
        self.active_sessions[target] = {"session": session}
        
        handshake_data = {
            "type": "HANDSHAKE_INIT",
            "sender": self.config.user_id,
            "payload": {
                "ephemeral_key": base64.b64encode(session.get_public_bytes()).decode('utf-8')
            }
        }
        self.network.send_message(peers[target]['address'], peers[target]['port'], handshake_data)
        self.log("network", f"Handshake sent to {target}")

    def _cmd_fetch(self, *args):
        target = input("Fetch list from: ")
        peers = self.discovery.get_active_peers()
        
        if target in peers:
            self.network.send_message(peers[target]['address'], peers[target]['port'], {
                "type": "FILE_LIST_REQUEST", "sender": self.config.user_id
            })
        else:
            print(f"[-] Peer '{target}' not found.")

    def _cmd_send(self, *args):
        target = input("Recipient: ")
        if target not in self.active_sessions or "encryptor" not in self.active_sessions[target]:
            return print("[-] Establish a secure connection first (use 'connect').")
        
        filename = input("Filename to send: ")
        file_path = self.shared_path / filename
        
        if not file_path.exists():
            return print(f"[-] File not found in {self.shared_path}/")

        # Encryption and Transfer
        data = file_path.read_bytes()
        encryptor = self.active_sessions[target]["encryptor"]
        nonce, ciphertext = encryptor.encrypt_data(data)
        
        peer_info = self.discovery.get_active_peers().get(target)
        self.network.send_message(peer_info['address'], peer_info['port'], {
            "type": "FILE_TRANSFER",
            "sender": self.config.user_id,
            "payload": {
                "filename": filename,
                "nonce": base64.b64encode(nonce).decode('utf-8'),
                "data": base64.b64encode(ciphertext).decode('utf-8')
            }
        })
        self.log("transfer", f"Dispatched encrypted file: {filename}")

    def _cmd_rotate(self, *args):
        self.key_mgr.generate_new_keys()
        self.log("security", "Identity keys rotated and saved.")

    def _cmd_exit(self, *args):
        self.shutdown()
        sys.exit(0)

    # --- HANDSHAKE & PROTOCOL LOGIC ---

    def _process_handshake_init(self, sender, payload, addr):
        """Responds to a connection request and derives the key."""
        session = SessionManager()
        try:
            peer_ephemeral_key = base64.b64decode(payload["ephemeral_key"])
            shared_key = session.derive_shared_secret(peer_ephemeral_key)
            
            # Upgrade session immediately for the responder
            self.active_sessions[sender] = {"encryptor": FileEncryptor(shared_key)}
            
            response = {
                "type": "HANDSHAKE_RESPONSE",
                "sender": self.config.user_id,
                "payload": {
                    "ephemeral_key": base64.b64encode(session.get_public_bytes()).decode('utf-8'),
                    "signature": base64.b64encode(session.sign_ephemeral_key(self.key_mgr.private_key)).decode('utf-8')
                }
            }
            
            # Respond to the peer's actual port from discovery if known, else the incoming addr
            peers = self.discovery.get_active_peers()
            peer_port = peers.get(sender, {}).get('port', addr[1])
            
            self.network.send_message(addr[0], peer_port, response)
            self.log("security", f"Secure tunnel established (Inbound) with {sender}")
        except Exception as e:
            self.log("error", f"Handshake failed with {sender}: {e}")

    def _process_handshake_response(self, sender, payload):
        """Finalizes the key derivation started by _cmd_connect."""
        if sender in self.active_sessions and "session" in self.active_sessions[sender]:
            try:
                session = self.active_sessions[sender]["session"]
                peer_ephemeral_key = base64.b64decode(payload["ephemeral_key"])
                shared_key = session.derive_shared_secret(peer_ephemeral_key)
                
                # Upgrade session from 'pending' (session object) to 'active' (encryptor)
                self.active_sessions[sender] = {"encryptor": FileEncryptor(shared_key)}
                self.log("security", f"Secure tunnel established (Outbound) with {sender}")
            except Exception as e:
                self.log("error", f"Failed to finalize session with {sender}: {e}")

    def _process_file_transfer(self, sender, payload):
        """Decrypts and saves files into the data_{user}/received folder."""
        if sender not in self.active_sessions or "encryptor" not in self.active_sessions[sender]:
            self.log("alert", f"Blocked unauthenticated transfer from {sender}")
            return
        
        try:
            nonce = base64.b64decode(payload["nonce"])
            ciphertext = base64.b64decode(payload["data"])
            encryptor = self.active_sessions[sender]["encryptor"]
            
            decrypted = encryptor.decrypt_data(nonce, ciphertext)

            if decrypted:
                save_dir = self.data_path / "received"
                self.storage.save_file(payload["filename"], decrypted, str(save_dir))
                self.log("success", f"Received: {payload['filename']} ({len(decrypted)} bytes)")
            else:
                self.log("alert", f"Decryption failed for {payload['filename']}!")
        except Exception as e:
            self.log("error", f"File transfer error: {e}")

    def _handle_list_request(self, sender):
        """Stub for handling file list requests."""
        self.log("network", f"{sender} requested a file list.")
        # Logic to send back file list can be added here

    # --- LIFECYCLE ---

    def run(self):
        banner = f" SECURE P2P: {self.config.user_id} (Port {self.config.port}) "
        print(f"\n{'='*50}\n{banner:^50}\n  Type 'help' for commands\n{'='*50}")
        
        self.discovery.start_discovery()
        self.network.start_server()
        
        try:
            while True:
                user_input = input(f"\n{self.config.user_id} > ").strip()
                if not user_input:
                    continue
                
                parts = user_input.split()
                cmd = parts[0].lower()
                args = parts[1:]
                
                if cmd in self.commands:
                    self.commands[cmd]["func"](*args)
                else:
                    print(f"[-] Unknown command '{cmd}'. Type 'help' for options.")
        except (KeyboardInterrupt, SystemExit):
            self.shutdown()

    def shutdown(self):
        self.log("system", "Shutting down services...")
        self.discovery.stop_discovery()
        self.network.stop()

if __name__ == "__main__":
    u_id = sys.argv[1] if len(sys.argv) > 1 else "Alice_Python"
    u_port = int(sys.argv[2]) if len(sys.argv) > 2 else 5000
    app = SecureP2PApp(user_id=u_id, port=u_port)
    app.run()