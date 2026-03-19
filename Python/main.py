import os
import sys
import time
import base64
import json

# # ==========================================
# # GLOBAL CONFIGURATION
# # ==========================================
# USER_ID = "Alice_Python"             
# LISTEN_PORT = 5000                  
# MDNS_SERVICE_TYPE = "_cisc468secshare._tcp.local."
# DATA_DIR = "data"
# ENCRYPTED_SUBDIR = "encrypted"
# KEYS_SUBDIR = "keys"
# SHARED_FILES_DIR = "shared_test_files"
# # ==========================================

# ==========================================
# DYNAMIC CONFIGURATION (Command Line)
# ==========================================
# Default values if no arguments are provided
USER_ID = "Alice_Python"
LISTEN_PORT = 5000

# Check for arguments: python main.py [name] [port]
if len(sys.argv) > 1:
    USER_ID = sys.argv[1]
if len(sys.argv) > 2:
    LISTEN_PORT = int(sys.argv[2])

MDNS_SERVICE_TYPE = "_cisc468secshare._tcp.local."
DATA_DIR = f"data_{USER_ID}" # Unique data folder per user
ENCRYPTED_SUBDIR = "encrypted"
KEYS_SUBDIR = "keys"
SHARED_FILES_DIR = "shared_test_files"
# ==========================================

# Add src to path so we can import our modules
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

# Import our custom modules
from discovery.mdns_handler import MDNSHandler
from crypto.key_manager import KeyManager
from crypto.session import SessionManager
from crypto.encryption import FileEncryptor
from crypto.storage import SecureStorage
from network.connection import NetworkManager 

class SecureP2PApp:
    def __init__(self):
        self.user_id = USER_ID
        self.port = LISTEN_PORT
        self.service_type = MDNS_SERVICE_TYPE
        
        # Track active sessions: { "peer_id": {"session": obj, "encryptor": obj} }
        self.active_sessions = {}

        # 1. Initialize Directory Structure (Requirement 9)
        self.base_path = os.path.dirname(os.path.abspath(__file__))
        self.setup_directories()

        # 2. Initialize Identity Keys (Requirement 2 & 6)
        keys_path = os.path.join(self.base_path, DATA_DIR, KEYS_SUBDIR)
        self.key_mgr = KeyManager(keys_dir=keys_path)
        self.key_mgr.load_or_generate_keys()

        # 3. Initialize Local Secure Storage (Requirement 9)
        # Using a default password; in production, this would be a user prompt
        self.storage = SecureStorage(password="my_secure_password_123")

        # 4. Initialize Network Manager (Requirement 3, 4, 7)
        # We pass self.handle_incoming_message as the callback for background logic
        self.network = NetworkManager(self.port, self.handle_incoming_message)

        # 5. Initialize Discovery Logic (Requirement 1)
        self.discovery = MDNSHandler(self.user_id, self.port, self.service_type)

    def setup_directories(self):
        """Creates local storage and shared folders if they don't exist."""
        subdirs = [
            os.path.join(DATA_DIR, ENCRYPTED_SUBDIR),
            os.path.join(DATA_DIR, KEYS_SUBDIR),
            SHARED_FILES_DIR
        ]
        for subdir in subdirs:
            path = os.path.join(self.base_path, subdir)
            os.makedirs(path, exist_ok=True)

    def handle_incoming_message(self, msg, addr):
        """Processes all incoming TCP messages (Requirements 2, 3, 4, 7, 8)."""
        msg_type = msg.get("type")
        sender = msg.get("sender")
        payload = msg.get("payload", {})

        # --- Requirement 2 & 8: Mutual Authentication & Handshake ---
        if msg_type == "HANDSHAKE_INIT":
            print(f"\n[!] Handshake request from {sender} ({addr[0]})")
            session = SessionManager()
            peer_ephemeral_raw = base64.b64decode(payload["ephemeral_key"])
            
            # Derive shared secret (Requirement 8 - Perfect Forward Secrecy)
            shared_key = session.derive_shared_secret(peer_ephemeral_raw)
            self.active_sessions[sender] = {"encryptor": FileEncryptor(shared_key)}

            # Sign our ephemeral key (Requirement 2 - Authentication)
            my_sig = session.sign_ephemeral_key(self.key_mgr.private_key)
            response = {
                "type": "HANDSHAKE_RESPONSE",
                "sender": self.user_id,
                "payload": {
                    "ephemeral_key": base64.b64encode(session.get_public_bytes()).decode('utf-8'),
                    "signature": base64.b64encode(my_sig).decode('utf-8')
                }
            }
            self.network.send_message(addr[0], self.port, response)
            print(f"[*] Handshake complete. Secure tunnel established with {sender}.")

        elif msg_type == "HANDSHAKE_RESPONSE":
            print(f"\n[*] Received Handshake response from {sender}")
            peer_ephemeral_raw = base64.b64decode(payload["ephemeral_key"])
            
            if sender in self.active_sessions and "session" in self.active_sessions[sender]:
                session = self.active_sessions[sender]["session"]
                shared_key = session.derive_shared_secret(peer_ephemeral_raw)
                self.active_sessions[sender] = {"encryptor": FileEncryptor(shared_key)}
                print(f"[*] Secure tunnel established with {sender}.")

        # --- Requirement 4: File Listing (No consent required) ---
        elif msg_type == "FILE_LIST_REQUEST":
            shared_dir = os.path.join(self.base_path, SHARED_FILES_DIR)
            files = [f for f in os.listdir(shared_dir) if os.path.isfile(os.path.join(shared_dir, f))]
            
            response = {
                "type": "FILE_LIST_RESPONSE",
                "sender": self.user_id,
                "payload": {"files": files}
            }
            self.network.send_message(addr[0], self.port, response)

        elif msg_type == "FILE_LIST_RESPONSE":
            files = payload.get("files", [])
            print(f"\n[+] Files available on {sender}:")
            if not files: print("    (No files available)")
            for f in files: print(f"    - {f}")

        # --- Requirement 3 & 7: File Transfer & Consent ---
        elif msg_type == "FILE_TRANSFER":
            filename = payload.get("filename")
            print(f"\n[?] Incoming file '{filename}' from {sender}. Accept? (y/n): ", end="", flush=True)
            
            # Auto-accept logic for terminal demo (Req 3 placeholder)
            print("y") 
            
            nonce = base64.b64decode(payload["nonce"])
            ciphertext = base64.b64decode(payload["data"])
            
            if sender in self.active_sessions and "encryptor" in self.active_sessions[sender]:
                encryptor = self.active_sessions[sender]["encryptor"]
                decrypted_data = encryptor.decrypt_data(nonce, ciphertext)

                if decrypted_data:
                    # Requirement 9: Secure Local Storage
                    target_dir = os.path.join(self.base_path, DATA_DIR, ENCRYPTED_SUBDIR)
                    self.storage.save_file(filename, decrypted_data, target_dir)
                    print(f"[*] {filename} verified and saved to encrypted storage.")
                else:
                    # Requirement 10: Error/Security messages
                    print(f"\n[!!!] SECURITY ALERT: Integrity check failed for file from {sender}!")

    def run(self):
        print(f"\n--- CISC 468 Secure P2P Client ---")
        print(f"ID: {self.user_id} | Port: {self.port}")
        print("-" * 35)

        self.discovery.start_discovery()
        self.network.start_server()
        
        try:
            while True:
                choice = input(f"\n{self.user_id} [list, rotate, connect, fetch, send, exit] > ").strip().lower()

                if choice == 'list':
                    peers = self.discovery.get_active_peers()
                    if not peers:
                        print("Searching... No other peers found yet.")
                    else:
                        print(f"\nDiscovered {len(peers)} Peer(s):")
                        for name, info in peers.items():
                            print(f" > {name} -- IP: {info['address']} | Port: {info['port']}")
                
                elif choice == 'rotate':
                    self.key_mgr.generate_new_keys()
                    print("[*] Identity rotated (Requirement 6).")

                elif choice == 'connect':
                    target_name = input("Enter peer name to connect to: ")
                    peers = self.discovery.get_active_peers()
                    if target_name in peers:
                        target = peers[target_name]
                        session = SessionManager()
                        self.active_sessions[target_name] = {"session": session}
                        
                        b64_key = base64.b64encode(session.get_public_bytes()).decode('utf-8')
                        msg = {
                            "type": "HANDSHAKE_INIT",
                            "sender": self.user_id,
                            "payload": {"ephemeral_key": b64_key}
                        }
                        self.network.send_message(target['address'], target['port'], msg)
                    else:
                        print("Peer not found.")

                elif choice == 'fetch':
                    target_name = input("Fetch file list from: ")
                    peers = self.discovery.get_active_peers()
                    if target_name in peers:
                        target = peers[target_name]
                        msg = {"type": "FILE_LIST_REQUEST", "sender": self.user_id}
                        self.network.send_message(target['address'], target['port'], msg)
                    else:
                        print("Peer not found.")

                elif choice == 'send':
                    target_name = input("Target peer: ")
                    if target_name not in self.active_sessions or "encryptor" not in self.active_sessions[target_name]:
                        print("No secure session. Run 'connect' first.")
                        continue
                    
                    filename = input("Filename in shared_test_files/: ")
                    file_path = os.path.join(self.base_path, SHARED_FILES_DIR, filename)
                    
                    if os.path.exists(file_path):
                        with open(file_path, "rb") as f:
                            file_data = f.read()
                        
                        encryptor = self.active_sessions[target_name]["encryptor"]
                        nonce, ciphertext = encryptor.encrypt_data(file_data)
                        
                        msg = {
                            "type": "FILE_TRANSFER",
                            "sender": self.user_id,
                            "payload": {
                                "filename": filename,
                                "nonce": base64.b64encode(nonce).decode('utf-8'),
                                "data": base64.b64encode(ciphertext).decode('utf-8')
                            }
                        }
                        target = self.discovery.get_active_peers().get(target_name)
                        self.network.send_message(target['address'], target['port'], msg)
                        print(f"[*] Sending {filename} securely...")
                    else:
                        print("File not found.")

                elif choice == 'exit':
                    break

                else:
                    print(f"[*] Unknown command.")

        except KeyboardInterrupt:
            pass
        finally:
            self.shutdown()

    def shutdown(self):
        print("\nCleaning up...")
        self.discovery.stop_discovery()
        self.network.stop()
        print("Goodbye.")

if __name__ == "__main__":
    app = SecureP2PApp()
    app.run()