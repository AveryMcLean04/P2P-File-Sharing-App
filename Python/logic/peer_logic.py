import base64
import os
import hashlib
from typing import Dict, Any

class PeerLogic:
    """
    Core business logic for P2P interactions.
    Handles cryptographic handshakes, file transfer consent, and redundancy checks.
    """
    def __init__(self, app):
        self.app = app
        self.active_transfers: Dict[str, Any] = {}

    # --- Authentication & Key Exchange ---

    def initiate_handshake(self, target_id: str):
        """Generates the initial DH exchange payload to send to a peer."""
        try:
            my_id_pub = self.app.auth_manager.get_public_key()
            local_priv, local_pub = self.app.auth_manager.generate_ephemeral_pair()
            
            self.app.auth_manager.pending_handshakes[target_id] = local_priv
            signature = self.app.auth_manager.sign(local_pub)

            return {
                "type": "HANDSHAKE_INIT",
                "sender": self.app.user_id,
                "payload": {
                    "identity_key": base64.b64encode(my_id_pub).decode(),
                    "ephemeral_share": base64.b64encode(local_pub).decode(),
                    "signature": base64.b64encode(signature).decode()
                }
            }
        except Exception as e:
            self.app.log("error", f"Handshake generation failed: {e}")
            return None

    def process_handshake_init(self, sender: str, payload: dict, addr: tuple):
        """Processes an incoming request and establishes a secure session."""
        try:
            peer_id_pub = base64.b64decode(payload.get("identity_key"))
            peer_ephemeral_pub = base64.b64decode(payload.get("ephemeral_share"))
            peer_signature = base64.b64decode(payload.get("signature"))

            if not self.app.auth_manager.verify_signature(peer_id_pub, peer_signature, peer_ephemeral_pub):
                self.app.log("security", f"Handshake signature spoofing detected from {sender}!")
                return

            local_priv, local_pub = self.app.auth_manager.generate_ephemeral_pair()
            session_key = self.app.auth_manager.derive_shared_secret(peer_ephemeral_pub, local_priv)
            encryptor = self.app.auth_manager.create_encryptor(session_key)

            self.app.active_sessions[sender] = {
                "status": "SECURE-SESSION",
                "encryptor": encryptor,
                "peer_identity": peer_id_pub
            }

            my_signature = self.app.auth_manager.sign(local_pub)
            response = {
                "type": "HANDSHAKE_RESPONSE",
                "sender": self.app.user_id,
                "payload": {
                    "ephemeral_key": base64.b64encode(local_pub).decode(),
                    "signature": base64.b64encode(my_signature).decode(),
                    "identity_key": base64.b64encode(self.app.auth_manager.get_public_key()).decode()
                }
            }
            
            peer_info = self.app.discovery.peers.get(sender)
            target_ip = peer_info['ip'] if peer_info else addr[0]
            target_port = peer_info['port'] if peer_info else addr[1]

            self.app.network.send_message(target_ip, target_port, response)
            self.app.log("security", f"Secure session established with {sender}.")
            
            print(f"\r\033[K{self.app.user_id} > ", end="", flush=True)

        except Exception as e:
            self.app.log("error", f"Handshake Init Failed: {e}")

    def process_handshake_response(self, sender: str, payload: dict):
        """Completes the handshake initiated by us."""
        try:
            peer_ephemeral_pub = base64.b64decode(payload.get("ephemeral_key"))
            peer_signature = base64.b64decode(payload.get("signature"))
            peer_id_pub = base64.b64decode(payload.get("identity_key"))

            if not self.app.auth_manager.verify_signature(peer_id_pub, peer_signature, peer_ephemeral_pub):
                self.app.log("security", f"Invalid identity signature from {sender}!")
                return

            local_priv = self.app.auth_manager.pending_handshakes.get(sender)
            if not local_priv:
                self.app.log("error", f"No pending handshake found for {sender}.")
                return

            session_key = self.app.auth_manager.derive_shared_secret(peer_ephemeral_pub, local_priv)
            encryptor = self.app.auth_manager.create_encryptor(session_key)

            self.app.active_sessions[sender] = {
                "status": "SECURE-SESSION",
                "encryptor": encryptor,
                "peer_identity": peer_id_pub
            }
        
            del self.app.auth_manager.pending_handshakes[sender]
            self.app.log("security", f"Mutual trust established. {sender} is now SECURE.")
            print(f"\r\033[K{self.app.user_id} > ", end="", flush=True)
        except Exception as e:
            self.app.log("error", f"Handshake Response Failed: {e}")

    # --- Messaging & Catalog ---

    def process_chat_message(self, sender: str, payload: str):
        """Decrypts and displays an incoming text message."""
        session = self.app.active_sessions.get(sender)
        if not session: return

        try:
            decrypted = session["encryptor"].decrypt(base64.b64decode(payload))
            print(f"\r\033[K[CHAT] {sender}: {decrypted.decode('utf-8')}")
            print(f"{self.app.user_id} > ", end="", flush=True)
        except Exception:
            self.app.log("error", f"Failed to decrypt message from {sender}.")

    def request_file_list(self, target_id: str):
        """Asks a peer for their shared catalog."""
        peer = self.app.discovery.peers.get(target_id)
        if peer:
            self.app.network.send_message(peer['ip'], peer['port'], {
                "type": "FILE_LIST_REQUEST", "sender": self.app.user_id, "payload": {}
            })
            self.app.log("system", f"Syncing catalog with {target_id}...")

    def handle_list_request(self, sender: str, payload: dict = None):
        """Sends our catalog to a requesting peer."""
        files = self.app.disk_store.list_encrypted_files() 
        peer = self.app.discovery.peers.get(sender)
        if peer:
            self.app.network.send_message(peer['ip'], peer['port'], {
                "type": "FILE_LIST_RESPONSE", 
                "sender": self.app.user_id, 
                "payload": {"files": files}
            })

    def process_file_list_response(self, sender: str, payload: dict):
        """Displays the catalog received from a peer."""
        files = payload.get("files", [])
        print(f"\r\033[K[CATALOG] Peer '{sender}' offers {len(files)} files:")
        if not files:
            print("  > (Empty)")
        for f in files: 
            print(f"  > {f}")
        print(f"{self.app.user_id} > ", end="", flush=True)

    # --- Transfer Consent Logic ---

    def initiate_file_request(self, target_id: str, filename: str):
        """Standard 'Pull' request for a file."""
        peer = self.app.discovery.peers.get(target_id)
        if peer:
            self.app.network.send_message(peer['ip'], peer['port'], {
                "type": "TRANSFER_REQUEST",
                "sender": self.app.user_id,
                "payload": {"filename": filename}
            })
            self.app.log("transfer", f"Requested '{filename}' from {target_id}. Waiting for peer...")

    def handle_push_proposal(self, sender: str, payload: dict):
        """Triggered when someone wants to 'Send' a file to us."""
        filename = payload.get("filename")
        self.app.pending_transfer = {"sender": sender, "filename": filename, "type": "PUSH"}
        self.app.awaiting_consent = True
        
        print(f"\r\033[K\n\a[!PROPOSAL] {sender} wants to SEND you: {filename}")
        print("Action required: Type 'accept' or 'deny'")
        print(f"{self.app.user_id} > ", end="", flush=True)

    def handle_transfer_request(self, sender: str, payload: dict):
        """Triggered when someone wants to 'Download' a file from us."""
        filename = payload.get("filename")
        
        if getattr(self.app, "last_pushed_file", None) == filename:
            self.app.log("transfer", f"Auto-approving download of '{filename}' for {sender}.")
            self.execute_approved_transfer(sender, filename)
            self.app.last_pushed_file = None
            return

        self.app.pending_transfer = {"sender": sender, "filename": filename, "type": "PULL"}
        self.app.awaiting_consent = True
        print(f"\r\033[K\n\a[!REQUEST] {sender} wants to DOWNLOAD: {filename}")
        print("Action required: Type 'accept' or 'deny'")
        print(f"{self.app.user_id} > ", end="", flush=True)

    def execute_approved_transfer(self, sender: str, filename: str):
        """Encrypts and transmits the file after user consent."""
        session = self.app.active_sessions.get(sender)
        if not session:
            self.app.log("error", f"Transfer aborted: No secure session with {sender}.")
            return

        try:
            if filename not in self.app.disk_store.list_shared_files():
                self.app.disk_store.export_from_vault_to_shared(filename)
            
            file_data = self.app.disk_store.get_shared_file_content(filename)
            file_hash = hashlib.sha256(file_data).hexdigest()
            signature = self.app.auth_manager.sign(file_hash.encode())

            encrypted_file = session["encryptor"].encrypt(file_data)
            peer = self.app.discovery.peers.get(sender)
            
            if peer:
                self.app.network.send_message(peer['ip'], peer['port'], {
                    "type": "TRANSFER_ACCEPT", 
                    "sender": self.app.user_id,
                    "payload": {
                        "filename": filename,
                        "data": base64.b64encode(encrypted_file).decode(),
                        "sha256": file_hash,
                        "signature": base64.b64encode(signature).decode()
                    }
                })
                self.app.log("transfer", f"Transfer complete: '{filename}' sent to {sender}.")
        except Exception as e:
            self.app.log("error", f"Transfer execution failed: {e}")

    def handle_transfer_accept(self, sender: str, payload: dict):
        """Receives, verifies, and secures an incoming file."""
        session = self.app.active_sessions.get(sender)
        if not session: return

        filename = payload.get("filename")
        try:
            peer_pub_key = session["peer_identity"]
            sig = base64.b64decode(payload.get("signature"))
            received_hash = payload.get("sha256")
            
            if not self.app.auth_manager.verify_signature(peer_pub_key, sig, received_hash.encode()):
                self.app.log("security", f"CRITICAL: Identity signature mismatch on {filename}!")
                return

            encrypted_blob = base64.b64decode(payload.get("data"))
            decrypted_data = session["encryptor"].decrypt(encrypted_blob)
            
            if hashlib.sha256(decrypted_data).hexdigest() != received_hash:
                self.app.log("security", f"INTEGRITY ALERT: Hash mismatch for {filename}!")
                return

            if self.app.disk_store.save_to_vault(filename, decrypted_data):
                self.app.log("file", f"Securely received and stored: {filename}")
        except Exception as e:
            self.app.log("error", f"Transfer intake failed: {e}")
        
        print(f"{self.app.user_id} > ", end="", flush=True)

    # --- Redundancy & Maintenance ---

    def handle_redundancy_query(self, sender: str, payload: dict):
        """Responds if we hold a requested file for network redundancy."""
        filename = payload.get("filename")
        if filename in self.app.disk_store.list_encrypted_files():
            peer = self.app.discovery.peers.get(sender)
            if peer:
                self.app.network.send_message(peer['ip'], peer['port'], {
                    "type": "REDUNDANCY_OFFER",
                    "sender": self.app.user_id,
                    "payload": {"filename": filename}
                })

    def handle_peer_left(self, sender: str, payload: dict = None):
        """Cleanup session data when a peer leaves the network."""
        self.app.active_sessions.pop(sender, None)
        if hasattr(self.app, "discovery"):
            self.app.discovery.peers.pop(sender, None)
        self.app.log("network", f"Peer '{sender}' disconnected. Security context purged.")
        print(f"{self.app.user_id} > ", end="", flush=True)