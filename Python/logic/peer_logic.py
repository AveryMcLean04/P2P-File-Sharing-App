import base64
import os
import hashlib

class PeerLogic:
    def __init__(self, app):
        self.app = app
        self.peers = {} 
        self.active_transfers = {}

    # --- Auth & Key Exchange (Requirement 2, 8 & Key Migration) ---

    def process_handshake_init(self, sender, payload, addr):
        try:
            peer_id_pub = base64.b64decode(payload.get("identity_key"))
            peer_ephemeral_pub = base64.b64decode(payload.get("ephemeral_share"))
            peer_signature = base64.b64decode(payload.get("signature"))

            if not self.app.auth_manager.verify_signature(peer_id_pub, peer_signature, peer_ephemeral_pub):
                self.app.log("security", f"Handshake signature verification failed for {sender}!")
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
                "ephemeral_key": base64.b64encode(local_pub).decode(),
                "signature": base64.b64encode(my_signature).decode(),
                "identity_key": base64.b64encode(self.app.auth_manager.get_public_key()).decode()
            }
            
            peer = self.app.discovery.peers.get(sender)
            if peer:
                self.app.network.send_message(peer['ip'], peer['port'], {
                    "type": "HANDSHAKE_RESPONSE", "sender": self.app.user_id, "payload": response
                })
                self.app.log("security", f"Mutual Authentication successful with {sender}.")
        except Exception as e:
            self.app.log("error", f"Handshake Init Failed: {e}")

    def process_handshake_response(self, sender, payload):
        try:
            peer_ephemeral_pub = base64.b64decode(payload.get("ephemeral_key"))
            peer_signature = base64.b64decode(payload.get("signature"))
            peer_id_pub = base64.b64decode(payload.get("identity_key"))

            if not self.app.auth_manager.verify_signature(peer_id_pub, peer_signature, peer_ephemeral_pub):
                self.app.log("security", f"Invalid signature from {sender}!")
                return

            local_priv = self.app.auth_manager.pending_handshakes.get(sender)
            if not local_priv: return

            session_key = self.app.auth_manager.derive_shared_secret(peer_ephemeral_pub, local_priv)
            encryptor = self.app.auth_manager.create_encryptor(session_key)

            self.app.active_sessions[sender] = {
                "status": "SECURE-SESSION",
                "encryptor": encryptor,
                "peer_identity": peer_id_pub
            }
        
            del self.app.auth_manager.pending_handshakes[sender]
            self.app.log("security", f"Verified identity of {sender}. Session Secure.")
        except Exception as e:
            self.app.log("error", f"Handshake Response Failed: {e}")

    def initiate_handshake(self, target_id):
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

    def process_key_migration(self, sender, payload):
        try:
            old_pub = base64.b64decode(payload.get("old_identity"))
            new_pub = base64.b64decode(payload.get("new_identity"))
            sig = base64.b64decode(payload.get("migration_sig"))

            from cryptography.hazmat.primitives.asymmetric import ed25519
            ed25519.Ed25519PublicKey.from_public_bytes(old_pub).verify(sig, new_pub)
            
            self.app.log("security", f"Identity migrated for {sender}.")
            
            if sender in self.app.active_sessions:
                self.app.active_sessions[sender]["peer_identity"] = new_pub
                peer = self.app.discovery.peers.get(sender)
                if peer:
                    msg = self.initiate_handshake(sender)
                    if msg: self.app.network.send_message(peer['ip'], peer['port'], msg)
        except Exception as e:
            self.app.log("error", f"Rejected malicious migration from {sender}: {e}")
        self.app.log("system", f"{self.app.user_id} > ", end="")

    # --- Communication & Discovery ---

    def process_chat_message(self, sender, payload):
        try:
            encryptor = self.app.active_sessions[sender]["encryptor"]
            decrypted = encryptor.decrypt(base64.b64decode(payload))
            if decrypted:
                print(f"\r\033[K[ {sender} ]: {decrypted.decode('utf-8')}")
                self.app.log("system", f"{self.app.user_id} > ", end="")
        except Exception:
            self.app.log("error", "Decryption failed.")

    def request_file_list(self, target_id):
        peer = self.app.discovery.peers.get(target_id)
        if peer:
            self.app.network.send_message(peer['ip'], peer['port'], {
                "type": "FILE_LIST_REQUEST", "sender": self.app.user_id, "payload": {}
            })
            self.app.log("system", f"Requested file list from {target_id}...")

    def handle_list_request(self, sender, payload=None):
        files = self.app.disk_store.list_shared_files()
        peer = self.app.discovery.peers.get(sender)
        if peer:
            self.app.network.send_message(peer['ip'], peer['port'], {
                "type": "FILE_LIST_RESPONSE", "sender": self.app.user_id, "payload": {"files": files}
            })

    def process_file_list_response(self, sender, payload):
        files = payload.get("files", [])
        if not files:
            self.app.log("system", f"{sender} is not sharing any files.")
        else:
            self.app.log("system", f"--- Files from {sender} ({len(files)}) ---")
            for f in files: self.app.log("system", f"  > {f}")

    # --- File Transfer & Consent (Requirement 3 & 7) ---

    def initiate_file_request(self, target_id, filename):
        peer = self.app.discovery.peers.get(target_id)
        if peer:
            self.app.network.send_message(peer['ip'], peer['port'], {
                "type": "TRANSFER_REQUEST", "sender": self.app.user_id, "payload": {"filename": filename}
            })
            self.app.log("transfer", f"Sent request to {target_id} for '{filename}'. Waiting for consent...")

    def handle_transfer_request(self, sender, payload):
        filename = payload.get("filename")
        self.app.log("transfer", f"CONSENT REQUIRED: {sender} wants to download '{filename}'.")
        choice = input(f"Allow '{filename}' to be sent to {sender}? (y/n): ").strip().lower()
        
        peer = self.app.discovery.peers.get(sender)
        if choice == 'y' and peer:
            file_data = self.app.disk_store.get_shared_file_content(filename)
            encryptor = self.app.active_sessions[sender]["encryptor"]
            if file_data:
                encrypted_file = encryptor.encrypt(file_data)
                self.app.network.send_message(peer['ip'], peer['port'], {
                    "type": "TRANSFER_ACCEPT", "sender": self.app.user_id,
                    "payload": {"filename": filename, "data": base64.b64encode(encrypted_file).decode()}
                })
                self.app.log("transfer", f"File '{filename}' sent successfully.")
        elif peer:
            self.app.network.send_message(peer['ip'], peer['port'], {
                "type": "TRANSFER_REJECT", "sender": self.app.user_id, "payload": {"filename": filename}
            })
            self.app.log("transfer", "Transfer request denied.")
        self.app.log("system", f"{self.app.user_id} > ", end="")

    def handle_transfer_request(self, sender, payload):
        """
        Processes a request from a peer to download a file.
        Requires manual user consent, then encrypts, hashes, and signs the file.
        """
        filename = payload.get("filename")
        self.app.log("transfer", f"CONSENT REQUIRED: {sender} wants to download '{filename}'.")
        
        choice = input(f"Allow '{filename}' to be sent to {sender}? (y/n): ").strip().lower()
        
        peer = self.app.discovery.peers.get(sender)
        session = self.app.active_sessions.get(sender)

        if choice == 'y' and peer and session:
            try:
                file_data = self.app.disk_store.get_shared_file_content(filename)
                if not file_data:
                    self.app.log("error", f"File '{filename}' not found in shared folder.")
                    return

                file_hash = hashlib.sha256(file_data).hexdigest()
                signature = self.app.auth_manager.sign(file_hash.encode())

                encryptor = session["encryptor"]
                encrypted_file = encryptor.encrypt(file_data)

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
                self.app.log("transfer", f"File '{filename}' sent successfully with integrity guarantee.")

            except Exception as e:
                self.app.log("error", f"Failed to prepare file transfer: {e}")

        elif peer:
            self.app.network.send_message(peer['ip'], peer['port'], {
                "type": "TRANSFER_REJECT", 
                "sender": self.app.user_id, 
                "payload": {"filename": filename}
            })
            self.app.log("transfer", "Transfer request denied.")
        
        else:
            self.app.log("error", f"Cannot fulfill request: Peer {sender} session is inactive.")
            
        self.app.log("system", f"{self.app.user_id} > ", end="")

    def handle_transfer_accept(self, sender, payload):
        """
        Receives an encrypted file, verifies the cryptographic signature (Authenticity), 
        checks the SHA-256 hash (Integrity), and decrypts it (Confidentiality).
        """        
        filename = payload.get("filename")
        encoded_data = payload.get("data")
        received_hash = payload.get("sha256")
        encoded_sig = payload.get("signature")
        
        session = self.app.active_sessions.get(sender)
        if not session:
            self.app.log("security", f"DENIED: No secure session established with {sender}.")
            return

        try:
            peer_pub_key = session["peer_identity"]
            signature = base64.b64decode(encoded_sig)
            
            if not self.app.auth_manager.verify_signature(peer_pub_key, signature, received_hash.encode()):
                self.app.log("security", f"CRITICAL: Signature mismatch on '{filename}'! Possible tampering.")
                return

            encryptor = session["encryptor"]
            encrypted_blob = base64.b64decode(encoded_data)
            decrypted_data = encryptor.decrypt(encrypted_blob)
            
            if decrypted_data:
                actual_hash = hashlib.sha256(decrypted_data).hexdigest()
                
                if actual_hash != received_hash:
                    self.app.log("security", f"INTEGRITY FAILURE: SHA-256 mismatch for '{filename}'!")
                    return

                if self.app.disk_store.save_to_vault(filename, decrypted_data):
                    self.app.log("file", f"Verified & Received '{filename}' from {sender}. Secured in Vault.")
            else:
                self.app.log("security", "GCM Decryption failed: Data blob is invalid or key mismatch.")
                
        except Exception as e:
            self.app.log("error", f"Processing failed for file transfer: {e}")
            
        self.app.log("system", f"{self.app.user_id} > ", end="")

    def handle_transfer_reject(self, sender, payload):
        filename = payload.get("filename")
        self.app.log("transfer", f"Peer {sender} DENIED your request for '{filename}'.")
        self.app.log("system", f"{self.app.user_id} > ", end="")

    # --- Redundancy & Maintenance (Requirement 5) ---

    def handle_redundancy_offer(self, sender, payload):
        filename = payload.get("filename")
        self.app.log("system", f"REDUNDANCY ALERT: {sender} has a backup of '{filename}'.")
        self.app.log("system", f"{self.app.user_id} > ", end="")

    def handle_peer_left(self, sender, payload=None):
        self.app.active_sessions.pop(sender, None)
        if hasattr(self.app, "discovery"):
            self.app.discovery.peers.pop(sender, None)
        self.app.log("network", f"Peer {sender} disconnected.")
        self.app.log("system", f"{self.app.user_id} > ", end="")