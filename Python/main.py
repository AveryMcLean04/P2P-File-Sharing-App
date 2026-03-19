import os
import sys
import time
import base64
import hashlib
from pathlib import Path
from dataclasses import dataclass

# Path setup and internal imports
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
        
        # [REQ #5] Track file hashes globally for verification
        self.global_registry = {} # {"filename": {"original_owner": str, "hash": str}}

        # Path definitions
        self.data_path = self.base_path / self.config.data_dir_name
        self.shared_path = self.base_path / self.config.shared_dir_name
        self._setup_directories()

        # [REQ #9] Secure storage uses a password for encryption at rest
        self.key_mgr = KeyManager(keys_dir=str(self.data_path / "keys"))
        self.key_mgr.load_or_generate_keys()
        
        self.storage = SecureStorage(password="my_secure_password_123")
        self.network = NetworkManager(self.config.port, self.handle_incoming_message)
        self.discovery = MDNSHandler(self.config.user_id, self.config.port, self.config.service_type)

        self.commands = {
            "help":    {"func": self._cmd_help,    "desc": "Show all available commands"},
            "list":    {"func": self._cmd_list,    "desc": "List discovered network peers (mDNS)"},
            "find":    {"func": self._cmd_find,    "desc": "Search for offline peer's files (Req #5)"},
            "connect": {"func": self._cmd_connect, "desc": "Establish secure session (PFS Handshake)"},
            "fetch":   {"func": self._cmd_fetch,   "desc": "Request file list from a peer (Req #4)"},
            "send":    {"func": self._cmd_send,    "desc": "Send file with consent (Req #3)"},
            "rotate":  {"func": self._cmd_rotate,  "desc": "Rotate identity keys (Req #6)"},
            "exit":    {"func": self._cmd_exit,    "desc": "Safely shut down"}
        }

    def _setup_directories(self):
        (self.data_path / "keys").mkdir(parents=True, exist_ok=True)
        (self.data_path / "received").mkdir(parents=True, exist_ok=True)
        self.shared_path.mkdir(parents=True, exist_ok=True)

    def log(self, category, message):
        timestamp = time.strftime('%H:%M:%S')
        print(f"[{timestamp}] [{category.upper():^10}] {message}")

    # --- NETWORK DISPATCHER ---

    def handle_incoming_message(self, message, addr):
        m_type = message.get("type")
        sender = message.get("sender")
        payload = message.get("payload")

        handlers = {
            "HANDSHAKE_INIT":    lambda: self._process_handshake_init(sender, payload, addr),
            "HANDSHAKE_RESPONSE":lambda: self._process_handshake_response(sender, payload),
            "FILE_LIST_REQUEST": lambda: self._handle_list_request(sender),
            "FILE_LIST_RESPONSE":lambda: self._process_list_response(sender, payload),
            "TRANSFER_REQUEST":  lambda: self._handle_transfer_request(sender, payload),
            "TRANSFER_ACCEPT":   lambda: self._handle_transfer_accept(sender, payload),
            "FILE_DATA_PACKET":  lambda: self._process_file_transfer(sender, payload),
            "TRANSFER_REJECT":   lambda: self.log("transfer", f"{sender} rejected the transfer."),
            "REDUNDANCY_QUERY":  lambda: self._handle_redundancy_query(sender, payload),
            "REDUNDANCY_OFFER":  lambda: self._handle_redundancy_offer(sender, payload)
        }

        if m_type in handlers:
            handlers[m_type]()
        else:
            self.log("network", f"Unknown message type from {sender}: {m_type}")

    # --- [REQ #4] FILE LISTING LOGIC ---

    def _handle_list_request(self, sender):
        file_info = {}
        for f in self.shared_path.iterdir():
            if f.is_file():
                # Hash the file so the requester can verify it later (Req #5)
                data = f.read_bytes()
                file_info[f.name] = hashlib.sha256(data).hexdigest()
        
        peer = self.discovery.get_active_peers().get(sender)
        if peer:
            self.network.send_message(peer['address'], peer['port'], {
                "type": "FILE_LIST_RESPONSE", "sender": self.config.user_id,
                "payload": {"files": file_info}
            })

    def _process_list_response(self, sender, payload):
        files = payload.get("files", {})
        print(f"\n--- Files available from {sender} ---")
        for name, f_hash in files.items():
            self.global_registry[name] = {"original_owner": sender, "hash": f_hash}
            print(f"  - {name} (Hash: {f_hash[:8]}...)")

    # --- [REQ #3] CONSENT-BASED TRANSFER ---

    def _cmd_send(self, *args):
        target = input("Recipient: ")
        filename = input("Filename to send: ")
        file_path = self.shared_path / filename

        if not file_path.exists():
            return print("[-] File not found.")
        
        if target not in self.active_sessions or "encryptor" not in self.active_sessions[target]:
            return print("[-] No secure session. Connect first.")

        peer = self.discovery.get_active_peers().get(target)
        self.network.send_message(peer['address'], peer['port'], {
            "type": "TRANSFER_REQUEST", "sender": self.config.user_id,
            "payload": {"filename": filename, "size": file_path.stat().st_size}
        })
        self.log("transfer", f"Transfer request for '{filename}' sent to {target}.")

    def _handle_transfer_request(self, sender, payload):
        fname = payload.get("filename")
        print(f"\n[!] ALERT: {sender} wants to send '{fname}'. Accept? (y/n)")
        choice = input(f"{self.config.user_id} > ").strip().lower()

        peer = self.discovery.get_active_peers().get(sender)
        m_type = "TRANSFER_ACCEPT" if choice == 'y' else "TRANSFER_REJECT"
        
        self.network.send_message(peer['address'], peer['port'], {
            "type": m_type, "sender": self.config.user_id, "payload": {"filename": fname}
        })

    def _handle_transfer_accept(self, sender, payload):
        fname = payload.get("filename")
        file_path = self.shared_path / fname
        encryptor = self.active_sessions[sender]["encryptor"]
        
        # [REQ #7 & #8] Encrypt data using session key (PFS)
        data = file_path.read_bytes()
        nonce, ciphertext = encryptor.encrypt_data(data)
        
        peer = self.discovery.get_active_peers().get(sender)
        self.network.send_message(peer['address'], peer['port'], {
            "type": "FILE_DATA_PACKET", "sender": self.config.user_id,
            "payload": {
                "filename": fname,
                "nonce": base64.b64encode(nonce).decode('utf-8'),
                "data": base64.b64encode(ciphertext).decode('utf-8')
            }
        })
        self.log("success", f"File '{fname}' dispatched to {sender}.")

    def _handle_redundancy_query(self, sender, payload):
        fname = payload["filename"]
        required_hash = payload["hash"]
    
        # Check both shared folder AND received folder
        paths_to_check = [self.shared_path / fname, self.data_path / "received" / fname]
    
        for path in paths_to_check:
            if path.exists():
                # Verify the file still matches the hash before offering it
                current_hash = hashlib.sha256(path.read_bytes()).hexdigest()
                if current_hash == required_hash:
                    peer = self.discovery.get_active_peers().get(sender)
                    self.network.send_message(peer['address'], peer['port'], {
                        "type": "REDUNDANCY_OFFER",
                        "sender": self.config.user_id,
                        "payload": {"filename": fname}
                    })
                    return

    def _handle_redundancy_offer(self, sender, payload):
        fname = payload["filename"]
        self.log("success", f"Found redundancy! {sender} has a verified copy of '{fname}'.")
        print(f"[!] Would you like to request '{fname}' from {sender}? (y/n)")
    
        # Note: In a real app, you might automate this or call _cmd_connect if not connected
        if sender not in self.active_sessions:
            print(f"[*] Hint: Use 'connect {sender}' then request the file.")

    # --- [REQ #5 & #10] VERIFICATION & ERROR HANDLING ---

    def _process_file_transfer(self, sender, payload):
        try:
            encryptor = self.active_sessions[sender]["encryptor"]
            nonce = base64.b64decode(payload["nonce"])
            ciphertext = base64.b64decode(payload["data"])
            decrypted = encryptor.decrypt_data(nonce, ciphertext)
            
            fname = payload["filename"]
            actual_hash = hashlib.sha256(decrypted).hexdigest()
            registry_entry = self.global_registry.get(fname)
            
            # [REQ #5] Tamper detection
            if registry_entry and actual_hash != registry_entry["hash"]:
                self.log("alert", f"TAMPERING DETECTED: {fname} does not match original owner's hash!")
                return

            # [REQ #9] Secure Local Storage (Encrypted at rest)
            save_path = str(self.data_path / "received")
            self.storage.save_file(fname, decrypted, save_path)
            self.log("success", f"Received and verified {fname} (Saved securely).")
            
        except Exception as e:
            self.log("error", f"Transfer failure: {e}")

    # --- CRYPTO & DISCOVERY HANDLERS ---

    def _process_handshake_init(self, sender, payload, addr):
        session = SessionManager()
        try:
            peer_key = base64.b64decode(payload["ephemeral_key"])
            shared_key = session.derive_shared_secret(peer_key)
            self.active_sessions[sender] = {"encryptor": FileEncryptor(shared_key)}
            
            response = {
                "type": "HANDSHAKE_RESPONSE", "sender": self.config.user_id,
                "payload": {"ephemeral_key": base64.b64encode(session.get_public_bytes()).decode('utf-8')}
            }
            peers = self.discovery.get_active_peers()
            peer_port = peers.get(sender, {}).get('port', addr[1])
            self.network.send_message(addr[0], peer_port, response)
            self.log("security", f"Secure tunnel established with {sender}")
        except Exception as e:
            self.log("error", f"Handshake failed: {e}")

    def _process_handshake_response(self, sender, payload):
        if sender in self.active_sessions and "session" in self.active_sessions[sender]:
            session = self.active_sessions[sender]["session"]
            peer_key = base64.b64decode(payload["ephemeral_key"])
            shared_key = session.derive_shared_secret(peer_key)
            self.active_sessions[sender] = {"encryptor": FileEncryptor(shared_key)}
            self.log("security", f"Secure tunnel finalized with {sender}")

    # --- CLI & LIFECYCLE ---

    def _cmd_help(self, *args):
        print(f"\n{'COMMAND':<12} | {'DESCRIPTION'}")
        print("-" * 45)
        for cmd, info in self.commands.items():
            print(f"{cmd:<12} | {info['desc']}")

    def _cmd_list(self, *args):
        peers = self.discovery.get_active_peers()
        if not peers: return print("[-] No peers found.")
        for name, info in peers.items():
            status = "Locked" if name in self.active_sessions else "Open"
            print(f" > {name:<15} [{info['address']}:{info['port']}] {status}")

    def _cmd_find(self, *args):
        """Usage: find <filename> - Searches active peers for a file originally owned by someone else."""
        if not args: return print("[-] Specify a filename.")
        fname = args[0]
    
        if fname not in self.global_registry:
            return print(f"[-] No history of '{fname}'. Run 'fetch' on a peer first to index their files.")

        target_hash = self.global_registry[fname]["hash"]
        self.log("system", f"Searching network for {fname} (Hash: {target_hash[:8]}...)")

        # Ask every currently online peer if they have this specific file/hash
        for peer_name, info in self.discovery.get_active_peers().items():
            self.network.send_message(info['address'], info['port'], {
                "type": "REDUNDANCY_QUERY", 
                "sender": self.config.user_id,
                "payload": {"filename": fname, "hash": target_hash}
            })

    def _cmd_connect(self, *args):
        target = input("Connect to: ")
        peers = self.discovery.get_active_peers()
        if target in peers:
            session = SessionManager()
            self.active_sessions[target] = {"session": session}
            self.network.send_message(peers[target]['address'], peers[target]['port'], {
                "type": "HANDSHAKE_INIT", "sender": self.config.user_id,
                "payload": {"ephemeral_key": base64.b64encode(session.get_public_bytes()).decode('utf-8')}
            })
        else: print(f"[-] Peer '{target}' unknown.")

    def _cmd_fetch(self, *args):
        target = input("Fetch from: ")
        peers = self.discovery.get_active_peers()
        if target in peers:
            self.network.send_message(peers[target]['address'], peers[target]['port'], {
                "type": "FILE_LIST_REQUEST", "sender": self.config.user_id
            })

    def _cmd_rotate(self, *args):
        self.key_mgr.generate_new_keys()
        self.log("security", "Keys rotated locally. (Next: Notify contacts)")

    def _cmd_exit(self, *args):
        self.shutdown()
        sys.exit(0)

    def run(self):
        banner = f" SECURE P2P: {self.config.user_id} "
        print(f"\n{'='*50}\n{banner:^50}\n{'='*50}")
        self.discovery.start_discovery()
        self.network.start_server()
        try:
            while True:
                cmd_line = input(f"\n{self.config.user_id} > ").strip().split()
                if not cmd_line: continue
                cmd = cmd_line[0].lower()
                if cmd in self.commands: self.commands[cmd]["func"](*cmd_line[1:])
                else: print("[-] Unknown command.")
        except (KeyboardInterrupt, SystemExit): self.shutdown()

    def shutdown(self):
        self.log("system", "Shutting down...")
        self.discovery.stop_discovery()
        self.network.stop()

if __name__ == "__main__":
    u_id = sys.argv[1] if len(sys.argv) > 1 else "Alice_Python"
    u_port = int(sys.argv[2]) if len(sys.argv) > 2 else 5000
    app = SecureP2PApp(user_id=u_id, port=u_port)
    app.run()