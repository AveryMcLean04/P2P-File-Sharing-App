
# import os
# import sys
# import time
# import base64
# import json

# # # ==========================================
# # # GLOBAL CONFIGURATION
# # # ==========================================
# # USER_ID = "Alice_Python"             
# # LISTEN_PORT = 5000                  
# # MDNS_SERVICE_TYPE = "_cisc468secshare._tcp.local."
# # DATA_DIR = "data"
# # ENCRYPTED_SUBDIR = "encrypted"
# # KEYS_SUBDIR = "keys"
# # SHARED_FILES_DIR = "shared_test_files"
# # # ==========================================

# # ==========================================
# # DYNAMIC CONFIGURATION (Command Line)
# # ==========================================
# # Default values if no arguments are provided
# USER_ID = "Alice_Python"
# LISTEN_PORT = 5000

# # Check for arguments: python main.py [name] [port]
# if len(sys.argv) > 1:
#     USER_ID = sys.argv[1]
# if len(sys.argv) > 2:
#     LISTEN_PORT = int(sys.argv[2])

# MDNS_SERVICE_TYPE = "_cisc468secshare._tcp.local."
# DATA_DIR = f"data_{USER_ID}" # Unique data folder per user
# ENCRYPTED_SUBDIR = "encrypted"
# KEYS_SUBDIR = "keys"
# SHARED_FILES_DIR = "shared_test_files"
# # ==========================================

# # Add src to path so we can import our modules
# sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

# # Import our custom modules
# from discovery.mdns_handler import MDNSHandler
# from crypto.key_manager import KeyManager
# from crypto.session import SessionManager
# from crypto.encryption import FileEncryptor
# from crypto.storage import SecureStorage
# from network.connection import NetworkManager 

# class SecureP2PApp:
#     def __init__(self):
#         self.user_id = USER_ID
#         self.port = LISTEN_PORT
#         self.service_type = MDNS_SERVICE_TYPE
        
#         # Track active sessions: { "peer_id": {"session": obj, "encryptor": obj} }
#         self.active_sessions = {}

#         # 1. Initialize Directory Structure (Requirement 9)
#         self.base_path = os.path.dirname(os.path.abspath(__file__))
#         self.setup_directories()

#         # 2. Initialize Identity Keys (Requirement 2 & 6)
#         keys_path = os.path.join(self.base_path, DATA_DIR, KEYS_SUBDIR)
#         self.key_mgr = KeyManager(keys_dir=keys_path)
#         self.key_mgr.load_or_generate_keys()

#         # 3. Initialize Local Secure Storage (Requirement 9)
#         # Using a default password; in production, this would be a user prompt
#         self.storage = SecureStorage(password="my_secure_password_123")

#         # 4. Initialize Network Manager (Requirement 3, 4, 7)
#         # We pass self.handle_incoming_message as the callback for background logic
#         self.network = NetworkManager(self.port, self.handle_incoming_message)

#         # 5. Initialize Discovery Logic (Requirement 1)
#         self.discovery = MDNSHandler(self.user_id, self.port, self.service_type)

#     def setup_directories(self):
#         """Creates local storage and shared folders if they don't exist."""
#         subdirs = [
#             os.path.join(DATA_DIR, ENCRYPTED_SUBDIR),
#             os.path.join(DATA_DIR, KEYS_SUBDIR),
#             SHARED_FILES_DIR
#         ]
#         for subdir in subdirs:
#             path = os.path.join(self.base_path, subdir)
#             os.makedirs(path, exist_ok=True)

#     def handle_incoming_message(self, msg, addr):
#         """Processes all incoming TCP messages (Requirements 2, 3, 4, 7, 8)."""
#         msg_type = msg.get("type")
#         sender = msg.get("sender")
#         payload = msg.get("payload", {})

#         # --- Requirement 2 & 8: Mutual Authentication & Handshake ---
#         if msg_type == "HANDSHAKE_INIT":
#             print(f"\n[!] Handshake request from {sender} ({addr[0]})")
#             session = SessionManager()
#             peer_ephemeral_raw = base64.b64decode(payload["ephemeral_key"])
            
#             # Derive shared secret (Requirement 8 - Perfect Forward Secrecy)
#             shared_key = session.derive_shared_secret(peer_ephemeral_raw)
#             self.active_sessions[sender] = {"encryptor": FileEncryptor(shared_key)}

#             # Sign our ephemeral key (Requirement 2 - Authentication)
#             my_sig = session.sign_ephemeral_key(self.key_mgr.private_key)
#             response = {
#                 "type": "HANDSHAKE_RESPONSE",
#                 "sender": self.user_id,
#                 "payload": {
#                     "ephemeral_key": base64.b64encode(session.get_public_bytes()).decode('utf-8'),
#                     "signature": base64.b64encode(my_sig).decode('utf-8')
#                 }
#             }
#             self.network.send_message(addr[0], self.port, response)
#             print(f"[*] Handshake complete. Secure tunnel established with {sender}.")

#         elif msg_type == "HANDSHAKE_RESPONSE":
#             print(f"\n[*] Received Handshake response from {sender}")
#             peer_ephemeral_raw = base64.b64decode(payload["ephemeral_key"])
            
#             if sender in self.active_sessions and "session" in self.active_sessions[sender]:
#                 session = self.active_sessions[sender]["session"]
#                 shared_key = session.derive_shared_secret(peer_ephemeral_raw)
#                 self.active_sessions[sender] = {"encryptor": FileEncryptor(shared_key)}
#                 print(f"[*] Secure tunnel established with {sender}.")

#         # --- Requirement 4: File Listing (No consent required) ---
#         elif msg_type == "FILE_LIST_REQUEST":
#             shared_dir = os.path.join(self.base_path, SHARED_FILES_DIR)
#             files = [f for f in os.listdir(shared_dir) if os.path.isfile(os.path.join(shared_dir, f))]
            
#             response = {
#                 "type": "FILE_LIST_RESPONSE",
#                 "sender": self.user_id,
#                 "payload": {"files": files}
#             }
#             self.network.send_message(addr[0], self.port, response)

#         elif msg_type == "FILE_LIST_RESPONSE":
#             files = payload.get("files", [])
#             print(f"\n[+] Files available on {sender}:")
#             if not files: print("    (No files available)")
#             for f in files: print(f"    - {f}")

#         # --- Requirement 3 & 7: File Transfer & Consent ---
#         elif msg_type == "FILE_TRANSFER":
#             filename = payload.get("filename")
#             print(f"\n[?] Incoming file '{filename}' from {sender}. Accept? (y/n): ", end="", flush=True)
            
#             # Auto-accept logic for terminal demo (Req 3 placeholder)
#             print("y") 
            
#             nonce = base64.b64decode(payload["nonce"])
#             ciphertext = base64.b64decode(payload["data"])
            
#             if sender in self.active_sessions and "encryptor" in self.active_sessions[sender]:
#                 encryptor = self.active_sessions[sender]["encryptor"]
#                 decrypted_data = encryptor.decrypt_data(nonce, ciphertext)

#                 if decrypted_data:
#                     # Requirement 9: Secure Local Storage
#                     target_dir = os.path.join(self.base_path, DATA_DIR, ENCRYPTED_SUBDIR)
#                     self.storage.save_file(filename, decrypted_data, target_dir)
#                     print(f"[*] {filename} verified and saved to encrypted storage.")
#                 else:
#                     # Requirement 10: Error/Security messages
#                     print(f"\n[!!!] SECURITY ALERT: Integrity check failed for file from {sender}!")

#     def run(self):
#         print(f"\n--- CISC 468 Secure P2P Client ---")
#         print(f"ID: {self.user_id} | Port: {self.port}")
#         print("-" * 35)

#         self.discovery.start_discovery()
#         self.network.start_server()
        
#         try:
#             while True:
#                 choice = input(f"\n{self.user_id} [list, rotate, connect, fetch, send, exit] > ").strip().lower()

#                 if choice == 'list':
#                     peers = self.discovery.get_active_peers()
#                     if not peers:
#                         print("Searching... No other peers found yet.")
#                     else:
#                         print(f"\nDiscovered {len(peers)} Peer(s):")
#                         for name, info in peers.items():
#                             print(f" > {name} -- IP: {info['address']} | Port: {info['port']}")
                
#                 elif choice == 'rotate':
#                     self.key_mgr.generate_new_keys()
#                     print("[*] Identity rotated (Requirement 6).")

#                 elif choice == 'connect':
#                     target_name = input("Enter peer name to connect to: ")
#                     peers = self.discovery.get_active_peers()
#                     if target_name in peers:
#                         target = peers[target_name]
#                         session = SessionManager()
#                         self.active_sessions[target_name] = {"session": session}
                        
#                         b64_key = base64.b64encode(session.get_public_bytes()).decode('utf-8')
#                         msg = {
#                             "type": "HANDSHAKE_INIT",
#                             "sender": self.user_id,
#                             "payload": {"ephemeral_key": b64_key}
#                         }
#                         self.network.send_message(target['address'], target['port'], msg)
#                     else:
#                         print("Peer not found.")

#                 elif choice == 'fetch':
#                     target_name = input("Fetch file list from: ")
#                     peers = self.discovery.get_active_peers()
#                     if target_name in peers:
#                         target = peers[target_name]
#                         msg = {"type": "FILE_LIST_REQUEST", "sender": self.user_id}
#                         self.network.send_message(target['address'], target['port'], msg)
#                     else:
#                         print("Peer not found.")

#                 elif choice == 'send':
#                     target_name = input("Target peer: ")
#                     if target_name not in self.active_sessions or "encryptor" not in self.active_sessions[target_name]:
#                         print("No secure session. Run 'connect' first.")
#                         continue
                    
#                     filename = input("Filename in shared_test_files/: ")
#                     file_path = os.path.join(self.base_path, SHARED_FILES_DIR, filename)
                    
#                     if os.path.exists(file_path):
#                         with open(file_path, "rb") as f:
#                             file_data = f.read()
                        
#                         encryptor = self.active_sessions[target_name]["encryptor"]
#                         nonce, ciphertext = encryptor.encrypt_data(file_data)
                        
#                         msg = {
#                             "type": "FILE_TRANSFER",
#                             "sender": self.user_id,
#                             "payload": {
#                                 "filename": filename,
#                                 "nonce": base64.b64encode(nonce).decode('utf-8'),
#                                 "data": base64.b64encode(ciphertext).decode('utf-8')
#                             }
#                         }
#                         target = self.discovery.get_active_peers().get(target_name)
#                         self.network.send_message(target['address'], target['port'], msg)
#                         print(f"[*] Sending {filename} securely...")
#                     else:
#                         print("File not found.")

#                 elif choice == 'exit':
#                     break

#                 else:
#                     print(f"Unknown command.")

#         except KeyboardInterrupt:
#             pass
#         finally:
#             self.shutdown()

#     def shutdown(self):
#         print("\nCleaning up...")
#         self.discovery.stop_discovery()
#         self.network.stop()
#         print("Goodbye.")

# if __name__ == "__main__":
#     app = SecureP2PApp()
#     app.run()

# import os
# import sys
# import time
# import base64
# import json
# from dataclasses import dataclass

# # Add src to path
# sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

# # Custom module imports (assuming these exist in your src/ folder)
# try:
#     from discovery.mdns_handler import MDNSHandler
#     from crypto.key_manager import KeyManager
#     from crypto.session import SessionManager
#     from crypto.encryption import FileEncryptor
#     from crypto.storage import SecureStorage
#     from network.connection import NetworkManager
# except ImportError as e:
#     print(f"[-] Critical Error: Missing internal modules. {e}")
#     sys.exit(1)

# @dataclass
# class AppConfig:
#     """Stores application configuration to avoid global variables."""
#     user_id: str
#     port: int
#     service_type: str = "_cisc468secshare._tcp.local."
#     shared_dir: str = "shared_test_files"
    
#     @property
#     def data_dir(self):
#         return f"data_{self.user_id}"

# class SecureP2PApp:
#     def __init__(self, user_id="Alice_Python", port=5000):
#         self.config = AppConfig(user_id=user_id, port=port)
#         self.base_path = os.path.dirname(os.path.abspath(__file__))
        
#         # Peer state: { "peer_id": {"session": obj, "encryptor": obj} }
#         self.active_sessions = {}

#         # 1. Setup Environment
#         self._setup_directories()

#         # 2. Cryptography & Storage
#         keys_path = os.path.join(self.base_path, self.config.data_dir, "keys")
#         self.key_mgr = KeyManager(keys_dir=keys_path)
#         self.key_mgr.load_or_generate_keys()
        
#         # Local encrypted storage for received files
#         self.storage = SecureStorage(password="my_secure_password_123")

#         # 3. Networking & Discovery
#         self.network = NetworkManager(self.config.port, self.handle_incoming_message)
#         self.discovery = MDNSHandler(self.config.user_id, self.config.port, self.config.service_type)

#     def _setup_directories(self):
#         """Initializes folder structure."""
#         dirs = [
#             os.path.join(self.config.data_dir, "encrypted"),
#             os.path.join(self.config.data_dir, "keys"),
#             self.config.shared_dir
#         ]
#         for d in dirs:
#             os.makedirs(os.path.join(self.base_path, d), exist_ok=True)

#     def log(self, category, message):
#         """Consistent console output."""
#         timestamp = time.strftime("%H:%M:%S")
#         print(f"[{timestamp}] [{category.upper():^10}] {message}")

#     def handle_incoming_message(self, msg, addr):
#         """Main dispatcher for incoming network messages."""
#         m_type = msg.get("type")
#         sender = msg.get("sender")
#         payload = msg.get("payload", {})

#         if m_type == "HANDSHAKE_INIT":
#             self.log("security", f"Handshake request from {sender} ({addr[0]})")
#             session = SessionManager()
#             peer_ephemeral = base64.b64decode(payload["ephemeral_key"])
            
#             shared_key = session.derive_shared_secret(peer_ephemeral)
#             self.active_sessions[sender] = {"encryptor": FileEncryptor(shared_key)}

#             response = {
#                 "type": "HANDSHAKE_RESPONSE",
#                 "sender": self.config.user_id,
#                 "payload": {
#                     "ephemeral_key": base64.b64encode(session.get_public_bytes()).decode('utf-8'),
#                     "signature": base64.b64encode(session.sign_ephemeral_key(self.key_mgr.private_key)).decode('utf-8')
#                 }
#             }
#             self.network.send_message(addr[0], self.config.port, response)
#             self.log("security", f"Secure tunnel established with {sender}")

#         elif m_type == "HANDSHAKE_RESPONSE":
#             if sender in self.active_sessions and "session" in self.active_sessions[sender]:
#                 peer_ephemeral = base64.b64decode(payload["ephemeral_key"])
#                 session = self.active_sessions[sender]["session"]
#                 shared_key = session.derive_shared_secret(peer_ephemeral)
#                 self.active_sessions[sender] = {"encryptor": FileEncryptor(shared_key)}
#                 self.log("security", f"Secure tunnel established with {sender}")

#         elif m_type == "FILE_LIST_REQUEST":
#             path = os.path.join(self.base_path, self.config.shared_dir)
#             files = [f for f in os.listdir(path) if os.path.isfile(os.path.join(path, f))]
#             self.network.send_message(addr[0], self.config.port, {
#                 "type": "FILE_LIST_RESPONSE",
#                 "sender": self.config.user_id,
#                 "payload": {"files": files}
#             })

#         elif m_type == "FILE_LIST_RESPONSE":
#             files = payload.get("files", [])
#             print(f"\n--- Files available on {sender} ---")
#             for f in files: print(f"  - {f}")
#             if not files: print("  (No files found)")

#         elif m_type == "FILE_TRANSFER":
#             filename = payload.get("filename")
#             self.log("transfer", f"Receiving '{filename}' from {sender}...")
            
#             nonce = base64.b64decode(payload["nonce"])
#             ciphertext = base64.b64decode(payload["data"])
            
#             if sender in self.active_sessions:
#                 encryptor = self.active_sessions[sender]["encryptor"]
#                 decrypted = encryptor.decrypt_data(nonce, ciphertext)

#                 if decrypted:
#                     save_path = os.path.join(self.base_path, self.config.data_dir, "encrypted")
#                     self.storage.save_file(filename, decrypted, save_path)
#                     self.log("success", f"File '{filename}' verified and stored.")
#                 else:
#                     self.log("alert", f"Integrity check FAILED for file from {sender}!")

#     def run(self):
#         """Main User Interface Loop."""
#         print(f"\n{'='*50}")
#         print(f" SECURE P2P: {self.config.user_id} on Port {self.config.port}")
#         print(f"{'='*50}")

#         self.discovery.start_discovery()
#         self.network.start_server()
        
#         try:
#             while True:
#                 cmd = input(f"\n({self.config.user_id}) > ").strip().lower()
#                 if not cmd: continue

#                 if cmd == 'list':
#                     peers = self.discovery.get_active_peers()
#                     if not peers:
#                         print("[-] No peers discovered.")
#                     else:
#                         for name, info in peers.items():
#                             print(f" > {name:<15} [{info['address']}:{info['port']}]")

#                 elif cmd == 'rotate':
#                     self.key_mgr.generate_new_keys()
#                     self.log("system", "Identity keys rotated.")

#                 elif cmd == 'connect':
#                     target_name = input("Target peer: ")
#                     peers = self.discovery.get_active_peers()
#                     if target_name in peers:
#                         session = SessionManager()
#                         self.active_sessions[target_name] = {"session": session}
                        
#                         self.network.send_message(peers[target_name]['address'], peers[target_name]['port'], {
#                             "type": "HANDSHAKE_INIT",
#                             "sender": self.config.user_id,
#                             "payload": {"ephemeral_key": base64.b64encode(session.get_public_bytes()).decode('utf-8')}
#                         })
#                     else:
#                         print("[-] Peer not found.")

#                 elif cmd == 'fetch':
#                     target_name = input("Fetch list from: ")
#                     peers = self.discovery.get_active_peers()
#                     if target_name in peers:
#                         self.network.send_message(peers[target_name]['address'], peers[target_name]['port'], {
#                             "type": "FILE_LIST_REQUEST", "sender": self.config.user_id
#                         })

#                 elif cmd == 'send':
#                     target_name = input("Recipient: ")
#                     if target_name not in self.active_sessions or "encryptor" not in self.active_sessions[target_name]:
#                         print("[-] Secure session required. Run 'connect' first.")
#                         continue
                    
#                     filename = input("Filename: ")
#                     f_path = os.path.join(self.base_path, self.config.shared_dir, filename)
                    
#                     if os.path.exists(f_path):
#                         with open(f_path, "rb") as f:
#                             data = f.read()
                        
#                         enc = self.active_sessions[target_name]["encryptor"]
#                         nonce, ciphertext = enc.encrypt_data(data)
                        
#                         target = self.discovery.get_active_peers().get(target_name)
#                         self.network.send_message(target['address'], target['port'], {
#                             "type": "FILE_TRANSFER",
#                             "sender": self.config.user_id,
#                             "payload": {
#                                 "filename": filename,
#                                 "nonce": base64.b64encode(nonce).decode('utf-8'),
#                                 "data": base64.b64encode(ciphertext).decode('utf-8')
#                             }
#                         })
#                         self.log("transfer", f"Sent encrypted file: {filename}")
#                     else:
#                         print("[-] Local file not found.")

#                 elif cmd in ['exit', 'quit']:
#                     break
#                 else:
#                     print("Available: list, connect, fetch, send, rotate, exit")

#         except KeyboardInterrupt:
#             pass
#         finally:
#             self.shutdown()

#     def shutdown(self):
#         self.log("system", "Shutting down...")
#         self.discovery.stop_discovery()
#         self.network.stop()

# if __name__ == "__main__":
#     u_id = sys.argv[1] if len(sys.argv) > 1 else "Alice_Python"
#     u_port = int(sys.argv[2]) if len(sys.argv) > 2 else 5000
    
#     app = SecureP2PApp(user_id=u_id, port=u_port)
#     app.run()


import os
import sys
import time
import base64
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
    user_id: str
    port: int
    service_type: str = "_cisc468secshare._tcp.local."
    shared_dir: str = "shared_test_files"
    
    @property
    def data_dir(self):
        return f"data_{self.user_id}"

class SecureP2PApp:
    def __init__(self, user_id="Alice_Python", port=5000):
        self.config = AppConfig(user_id=user_id, port=port)
        self.base_path = os.path.dirname(os.path.abspath(__file__))
        self.active_sessions = {}

        # Initialization modules
        self._setup_directories()
        self.key_mgr = KeyManager(keys_dir=os.path.join(self.base_path, self.config.data_dir, "keys"))
        self.key_mgr.load_or_generate_keys()
        self.storage = SecureStorage(password="my_secure_password_123")
        self.network = NetworkManager(self.config.port, self.handle_incoming_message)
        self.discovery = MDNSHandler(self.config.user_id, self.config.port, self.config.service_type)

        # Command Mapping for CLI
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
        for d in ["encrypted", "keys"]:
            os.makedirs(os.path.join(self.base_path, self.config.data_dir, d), exist_ok=True)
        os.makedirs(os.path.join(self.base_path, self.config.shared_dir), exist_ok=True)

    def log(self, category, message):
        print(f"[{time.strftime('%H:%M:%S')}] [{category.upper():^10}] {message}")

    # --- CLI COMMAND METHODS ---

    def _cmd_help(self, *args):
        print(f"\n{'COMMAND':<12} | {'DESCRIPTION'}")
        print("-" * 45)
        for cmd, info in self.commands.items():
            print(f"{cmd:<12} | {info['desc']}")

    def _cmd_list(self, *args):
        peers = self.discovery.get_active_peers()
        if not peers:
            print("[-] No peers discovered on the network.")
            return
        for name, info in peers.items():
            status = "?? Secured" if name in self.active_sessions else "?? Open"
            print(f" > {name:<15} [{info['address']}:{info['port']}] {status}")

    def _cmd_connect(self, *args):
        target = input("Connect to peer ID: ")
        peers = self.discovery.get_active_peers()
        if target in peers:
            session = SessionManager()
            self.active_sessions[target] = {"session": session}
            self.network.send_message(peers[target]['address'], peers[target]['port'], {
                "type": "HANDSHAKE_INIT",
                "sender": self.config.user_id,
                "payload": {"ephemeral_key": base64.b64encode(session.get_public_bytes()).decode('utf-8')}
            })
            self.log("network", f"Handshake sent to {target}")
        else:
            print(f"[-] Peer '{target}' not found.")

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
            print("[-] Establish a secure connection first (use 'connect').")
            return
        
        filename = input("Filename to send: ")
        f_path = os.path.join(self.base_path, self.config.shared_dir, filename)
        
        if os.path.exists(f_path):
            with open(f_path, "rb") as f:
                data = f.read()
            
            enc = self.active_sessions[target]["encryptor"]
            nonce, ciphertext = enc.encrypt_data(data)
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
        else:
            print(f"[-] File not found in {self.config.shared_dir}/")

    def _cmd_rotate(self, *args):
        self.key_mgr.generate_new_keys()
        self.log("security", "Identity keys rotated and saved.")

    def _cmd_exit(self, *args):
        self.shutdown()
        sys.exit(0)

    # --- MESSAGE HANDLING ---

    def handle_incoming_message(self, msg, addr):
        m_type = msg.get("type")
        sender = msg.get("sender")
        payload = msg.get("payload", {})

        if m_type == "HANDSHAKE_INIT":
            self._process_handshake_init(sender, payload, addr)
        elif m_type == "HANDSHAKE_RESPONSE":
            self._process_handshake_response(sender, payload)
        elif m_type == "FILE_LIST_REQUEST":
            self._process_file_list_request(addr)
        elif m_type == "FILE_LIST_RESPONSE":
            self._process_file_list_response(sender, payload)
        elif m_type == "FILE_TRANSFER":
            self._process_file_transfer(sender, payload)

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
        path = os.path.join(self.base_path, self.config.shared_dir)
        files = [f for f in os.listdir(path) if os.path.isfile(os.path.join(path, f))]
        self.network.send_message(addr[0], self.config.port, {
            "type": "FILE_LIST_RESPONSE", "sender": self.config.user_id, "payload": {"files": files}
        })

    def _process_file_list_response(self, sender, payload):
        print(f"\n--- Shared Files from {sender} ---")
        for f in payload.get("files", []): print(f"  - {f}")

    def _process_file_transfer(self, sender, payload):
        if sender not in self.active_sessions: return
        
        nonce = base64.b64decode(payload["nonce"])
        ciphertext = base64.b64decode(payload["data"])
        decrypted = self.active_sessions[sender]["encryptor"].decrypt_data(nonce, ciphertext)

        if decrypted:
            save_path = os.path.join(self.base_path, self.config.data_dir, "encrypted")
            self.storage.save_file(payload["filename"], decrypted, save_path)
            self.log("success", f"Received and verified: {payload['filename']}")
        else:
            self.log("alert", f"Integrity check failed for file from {sender}!")

    # --- EXECUTION ---

    def run(self):
        print(f"\n{'='*50}\n  SECURE P2P: {self.config.user_id} (Port {self.config.port})\n  Type 'help' for commands\n{'='*50}")
        self.discovery.start_discovery()
        self.network.start_server()
        
        try:
            while True:
                user_input = input(f"\n{self.config.user_id} > ").strip().lower().split()
                if not user_input: continue
                
                cmd = user_input[0]
                if cmd in self.commands:
                    self.commands[cmd]["func"](*user_input[1:])
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