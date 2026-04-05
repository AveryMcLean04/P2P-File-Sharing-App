import base64
import os
import hashlib
from typing import Dict, Any

class PeerLogic:
    """
    Core business logic for P2P interactions.
    Handles cryptographic handshakes, file transfers, and identity migration.
    """
    def __init__(self, app):
        self.app = app
        self.active_transfers: Dict[str, Any] = {}

    # --- Authentication & Key Exchange ---

    def initiate_handshake(self, target_id: str):
        """Generates the initial DH exchange payload for a target peer."""
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
                self.app.log("security", f"Handshake spoofing detected from {sender}!")
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
            t_ip, t_port = (peer_info['ip'], peer_info['port']) if peer_info else addr
            self.app.network.send_message(t_ip, t_port, response)
            self.app.log("security", f"Secure session established with {sender}.")
            print(f"\r\033[K{self.app.user_id} > ", end="", flush=True)

        except Exception as e:
            self.app.log("error", f"Handshake Init Failed: {e}")

    def process_handshake_response(self, sender: str, payload: dict):
        """Completes the handshake initiated by this node."""
        try:
            peer_ephemeral_pub = base64.b64decode(payload.get("ephemeral_key"))
            peer_signature = base64.b64decode(payload.get("signature"))
            peer_id_pub = base64.b64decode(payload.get("identity_key"))

            if not self.app.auth_manager.verify_signature(peer_id_pub, peer_signature, peer_ephemeral_pub):
                self.app.log("security", f"Invalid identity signature from {sender}!")
                return

            local_priv = self.app.auth_manager.pending_handshakes.get(sender)
            if not local_priv: return

            session_key = self.app.auth_manager.derive_shared_secret(peer_ephemeral_pub, local_priv)
            self.app.active_sessions[sender] = {
                "status": "SECURE-SESSION",
                "encryptor": self.app.auth_manager.create_encryptor(session_key),
                "peer_identity": peer_id_pub
            }
        
            del self.app.auth_manager.pending_handshakes[sender]
            self.app.log("security", f"Mutual trust established with {sender}.")
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
        except: self.app.log("error", f"Decryption failed from {sender}.")

    def request_file_list(self, target_id: str):
        """Requests the shared file catalog from a specific peer."""
        peer = self.app.discovery.peers.get(target_id)
        if peer:
            self.app.network.send_message(peer['ip'], peer['port'], {
                "type": "FILE_LIST_REQUEST", "sender": self.app.user_id, "payload": {}
            })
            self.app.log("system", f"Syncing catalog with {target_id}...")

    def handle_list_request(self, sender: str, payload: dict = None):
        """Sends our local catalog to a requesting peer."""
        files = self.app.disk_store.list_encrypted_files() 
        peer = self.app.discovery.peers.get(sender)
        if peer:
            self.app.network.send_message(peer['ip'], peer['port'], {
                "type": "FILE_LIST_RESPONSE", "sender": self.app.user_id, "payload": {"files": files}
            })

    def process_file_list_response(self, sender: str, payload: dict):
        """Displays the file list received from a peer."""
        files = payload.get("files", [])
        print(f"\r\033[K[CATALOG] Peer '{sender}' offers {len(files)} files:")
        for f in files: print(f"  > {f}")
        print(f"{self.app.user_id} > ", end="", flush=True)

    # --- Transfer Consent Logic ---

    def initiate_file_request(self, target_id: str, filename: str):
        """Sends a formal request to download a file from a peer."""
        peer = self.app.discovery.peers.get(target_id)
        if peer:
            self.app.network.send_message(peer['ip'], peer['port'], {
                "type": "TRANSFER_REQUEST", "sender": self.app.user_id, "payload": {"filename": filename}
            })
            self.app.log("transfer", f"Requested '{filename}' from {target_id}.")

    def handle_push_proposal(self, sender: str, payload: dict):
        """Handles an incoming offer from a peer wanting to send a file."""
        filename = payload.get("filename")
        self.app.pending_transfer = {"sender": sender, "filename": filename, "type": "PUSH"}
        self.app.awaiting_consent = True
        print(f"\r\033[K\n\a[!PROPOSAL] {sender} wants to SEND: {filename}")
        print(f"Action: 'accept' or 'deny'\n{self.app.user_id} > ", end="", flush=True)

    def handle_transfer_request(self, sender: str, payload: dict):
        """Handles an incoming request from a peer wanting to download a file."""
        filename = payload.get("filename")
        if getattr(self.app, "last_pushed_file", None) == filename:
            self.execute_approved_transfer(sender, filename)
            self.app.last_pushed_file = None
            return
        self.app.pending_transfer = {"sender": sender, "filename": filename, "type": "PULL"}
        self.app.awaiting_consent = True
        print(f"\r\033[K\n\a[!REQUEST] {sender} wants to DOWNLOAD: {filename}")
        print(f"Action: 'accept' or 'deny'\n{self.app.user_id} > ", end="", flush=True)

    def execute_approved_transfer(self, sender: str, filename: str):
        """Transmits the requested file to the peer after consent."""
        session = self.app.active_sessions.get(sender)
        if not session: return
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
                    "type": "TRANSFER_ACCEPT", "sender": self.app.user_id,
                    "payload": {
                        "filename": filename, "sha256": file_hash,
                        "data": base64.b64encode(encrypted_file).decode(),
                        "signature": base64.b64encode(signature).decode()
                    }
                })
                self.app.log("transfer", f"Sent '{filename}' to {sender}.")
        except Exception as e: self.app.log("error", f"Transfer failed: {e}")

    def handle_transfer_accept(self, sender: str, payload: dict):
        """Verifies, decrypts, and saves an incoming file."""
        session = self.app.active_sessions.get(sender)
        if not session: return
        try:
            sig = base64.b64decode(payload.get("signature"))
            received_hash = payload.get("sha256")
            if not self.app.auth_manager.verify_signature(session["peer_identity"], sig, received_hash.encode()):
                self.app.log("security", "Signature mismatch on received file!")
                return

            decrypted = session["encryptor"].decrypt(base64.b64decode(payload.get("data")))
            if hashlib.sha256(decrypted).hexdigest() != received_hash:
                self.app.log("security", "Integrity hash mismatch!")
                return

            if self.app.disk_store.save_to_vault(payload.get("filename"), decrypted):
                self.app.log("file", f"Received and stored: {payload.get('filename')}")
        except Exception as e: self.app.log("error", f"Intake failed: {e}")
        print(f"{self.app.user_id} > ", end="", flush=True)

    # --- Redundancy & Maintenance ---

    def handle_redundancy_query(self, sender: str, payload: dict):
        """Offers a file if we have it to maintain network redundancy."""
        filename = payload.get("filename")
        if filename in self.app.disk_store.list_encrypted_files():
            peer = self.app.discovery.peers.get(sender)
            if peer:
                self.app.network.send_message(peer['ip'], peer['port'], {
                    "type": "REDUNDANCY_OFFER", "sender": self.app.user_id, "payload": {"filename": filename}
                })

    def handle_redundancy_offer(self, sender: str, payload: dict):
        """
        Processes a response from a peer who has the file we are searching for.
        Tracks which peers can provide redundancy for specific files.
        """
        filename = payload.get("filename")
        if not filename: return

        if filename not in self.active_transfers:
            self.active_transfers[filename] = []
        
        if sender not in self.active_transfers[filename]:
            self.active_transfers[filename].append(sender)
            self.app.log("system", f"Redundancy Match: Peer '{sender}' has a copy of '{filename}'.")
            
        print(f"\r\033[K[FOUND] '{filename}' is available on: {', '.join(self.active_transfers[filename])}")
        print(f"{self.app.user_id} > ", end="", flush=True)

    def initiate_key_migration(self):
        """Helper to trigger identity rotation."""
        self.rotate_identity()

    def process_key_migration(self, sender, payload):
        """Verifies and updates a peer's identity after they rotate keys."""
        try:
            new_key = base64.b64decode(payload.get("new_identity_key"))
            sig = base64.b64decode(payload.get("signature"))
            session = self.app.active_sessions.get(sender)
            if session and self.app.auth_manager.verify_signature(session["peer_identity"], sig, new_key):
                session["peer_identity"] = new_key
                if sender in self.app.discovery.peers:
                    self.app.discovery.peers[sender]["public_key"] = base64.b64encode(new_key).decode()
                self.app.log("security", f"Identity updated for {sender}.")
            else:
                self.app.log("security", f"Forged migration from {sender}!")
                self.app.active_sessions.pop(sender, None)
        except Exception as e: self.app.log("error", f"Migration failed: {e}")

    def rotate_identity(self):
        """Generates new keys and broadcasts proof-of-continuity to peers."""
        try:
            _, new_pub, sig = self.app.auth_manager.migrate_identity()
            message = {
                "type": "KEY_MIGRATION_NOTIFY", "sender": self.app.user_id,
                "payload": {
                    "new_identity_key": base64.b64encode(new_pub).decode(),
                    "signature": base64.b64encode(sig).decode()
                }
            }
            for peer_id, info in self.app.discovery.peers.items():
                self.app.network.send_message(info['ip'], info['port'], message)
            self.app.log("security", "Identity rotated and broadcasted.")
        except Exception as e: self.app.log("error", f"Rotation failed: {e}")

    # --- Lifecycle ---

    def handle_peer_left(self, sender: str, payload: dict = None):
        """Cleans up sessions and discovery data when a peer disconnects."""
        try:
            self.app.active_sessions.pop(sender, None)
            if getattr(self.app, "pending_transfer", None) and self.app.pending_transfer.get("sender") == sender:
                self.app.pending_transfer = None
                self.app.awaiting_consent = False
            self.app.discovery.peers.pop(sender, None)
            self.app.log("system", f"Cleaned up peer: {sender}")
            print(f"\r\033[K{self.app.user_id} > ", end="", flush=True)
        except Exception as e: self.app.log("error", f"Cleanup error for {sender}: {e}")