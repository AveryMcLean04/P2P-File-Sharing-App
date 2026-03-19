import os
import sys
import time
import base64
from pathlib import Path
from dataclasses import dataclass, field

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
        self.shared_path.mkdir(parents=True, exist_ok=True)

    def log(self, category, message):
        timestamp = time.strftime('%H:%M:%S')
        print(f"[{timestamp}] [{category.upper():^10}] {message}")

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
            status = "?? Secured" if name in self.active_sessions else "?? Open"
            print(f" > {name:<15} [{info['address']}:{info['port']}] {status}")

    def _cmd_connect(self, *args):
        target = input("Connect to peer ID: ")
        peers = self.discovery.get_active_peers()
        
        if target not in peers:
            return print(f"[-] Peer '{target}' not found.")

        session = SessionManager()
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

    # --- MESSAGE PROCESSING ---

    def handle_incoming_message(self, msg, addr):
        m_type = msg.get("type")
        sender = msg.get("sender")
        payload = msg.get("payload", {})

        handlers = {
            "HANDSHAKE_INIT": lambda: self._process_handshake_init(sender, payload, addr),
            "HANDSHAKE_RESPONSE": lambda: self._process_handshake_response(sender, payload),
            "FILE_LIST_REQUEST": lambda: self._process_file_list_request(addr),
            "FILE_LIST_RESPONSE": lambda: self._process_file_list_response(sender, payload),
            "FILE_TRANSFER": lambda: self._process_file_transfer(sender, payload)
        }
        
        if m_type in handlers:
            handlers[m_type]()

    def _process_handshake_init(self, sender, payload, addr):
        session = SessionManager()
        shared_key = session.derive_shared_secret(base64.b64decode(payload["ephemeral_key"]))
        self.active_sessions[sender] = {"encryptor": FileEncryptor(shared_key)}
        
        response = {
            "type": "HANDSHAKE_RESPONSE",
            "sender": self.config.user_id,
            "payload": {
                "ephemeral_key": base64.b64encode(session.get_public_bytes()).decode('utf-8'),
                "signature": base64.b64encode(session.sign_ephemeral_key(self.key_mgr.private_key)).decode('utf-8')
            }
        }
        self.network.send_message(addr[0], self.config.port, response)
        self.log("security", f"Secure tunnel established (Inbound) with {sender}")

    def _process_handshake_response(self, sender, payload):
        if sender in self.active_sessions and "session" in self.active_sessions[sender]:
            session = self.active_sessions[sender]["session"]
            shared_key = session.derive_shared_secret(base64.b64decode(payload["ephemeral_key"]))
            self.active_sessions[sender] = {"encryptor": FileEncryptor(shared_key)}
            self.log("security", f"Secure tunnel established (Outbound) with {sender}")

    def _process_file_list_request(self, addr):
        files = [f.name for f in self.shared_path.iterdir() if f.is_file()]
        self.network.send_message(addr[0], self.config.port, {
            "type": "FILE_LIST_RESPONSE", "sender": self.config.user_id, "payload": {"files": files}
        })

    def _process_file_list_response(self, sender, payload):
        print(f"\n--- Shared Files from {sender} ---")
        for f in payload.get("files", []): 
            print(f"  - {f}")

    def _process_file_transfer(self, sender, payload):
        if sender not in self.active_sessions: return
        
        nonce = base64.b64decode(payload["nonce"])
        ciphertext = base64.b64decode(payload["data"])
        decrypted = self.active_sessions[sender]["encryptor"].decrypt_data(nonce, ciphertext)

        if decrypted:
            save_path = self.data_path / "encrypted"
            self.storage.save_file(payload["filename"], decrypted, str(save_path))
            self.log("success", f"Received and verified: {payload['filename']}")
        else:
            self.log("alert", f"Integrity check failed for file from {sender}!")

    # --- LIFECYCLE ---

    def run(self):
        banner = f" SECURE P2P: {self.config.user_id} (Port {self.config.port}) "
        print(f"\n{'='*50}\n{banner:^50}\n  Type 'help' for commands\n{'='*50}")
        
        self.discovery.start_discovery()
        self.network.start_server()
        
        try:
            while True:
                raw_input = input(f"\n{self.config.user_id} > ").strip().lower().split()
                if not raw_input: continue
                
                cmd = raw_input[0]
                if cmd in self.commands:
                    self.commands[cmd]["func"](*raw_input[1:])
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
