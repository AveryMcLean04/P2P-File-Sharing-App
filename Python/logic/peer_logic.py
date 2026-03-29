import base64
import os
import hashlib

class PeerLogic:
    def __init__(self, app):
        self.app = app
        self.peers = {} 
        self.active_transfers = {}

    # --- Auth & Key Exchange ---

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

    # --- Communication & Discovery ---

    def process_chat_message(self, sender, payload):
        try:
            encryptor = self.app.active_sessions[sender]["encryptor"]
            decrypted = encryptor.decrypt(base64.b64decode(payload))
            if decrypted:
                print(f"\r\033[K[ {sender} ]: {decrypted.decode('utf-8')}")
                print(f"{self.app.user_id} > ", end="", flush=True)
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
        files = self.app.disk_store.list_encrypted_files() 
        peer = self.app.discovery.peers.get(sender)
        if peer:
            self.app.network.send_message(peer['ip'], peer['port'], {
                "type": "FILE_LIST_RESPONSE", 
                "sender": self.app.user_id, 
                "payload": {"files": files}
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
        """
        Sends a formal request to a peer to download a specific file.
        This triggers a 'TRANSFER_REQUEST' on their end.
        """
        peer = self.app.discovery.peers.get(target_id)
        if not peer:
            self.app.log("error", f"Peer '{target_id}' not found.")
            return

        message = {
            "type": "TRANSFER_REQUEST",
            "sender": self.app.user_id,
            "payload": {
                "filename": filename
            }
        }

        if self.app.network.send_message(peer['ip'], peer['port'], message):
            self.app.log("transfer", f"Request for '{filename}' sent to {target_id}. Waiting for approval...")
        else:
            self.app.log("error", f"Failed to reach {target_id}.")

    def handle_push_proposal(self, sender, payload):
        """Peer is offering to send us a file."""
        filename = payload.get("filename")
        self.app.pending_transfer = {"sender": sender, "filename": filename, "type": "PUSH"}
        
        print(f"\n{'!'*10} INCOMING FILE OFFER {'!'*10}")
        print(f"Peer '{sender}' wants to send you: {filename}")
        print(f"Type 'accept' to receive or 'deny' to cancel.")
        print(f"{self.app.user_id} > ", end="", flush=True)

    def handle_transfer_request(self, sender, payload):
        """Peer is requesting to download a file from us."""
        filename = payload.get("filename")
        
        if hasattr(self.app, "last_pushed_file") and self.app.last_pushed_file == filename:
            self.app.log("transfer", f"Auto-approving request for '{filename}' (previously offered).")
            self.execute_approved_transfer(sender, filename)
            del self.app.last_pushed_file
            return

        self.app.pending_transfer = {"sender": sender, "filename": filename, "type": "PULL"}
        print(f"\n{'*'*10} TRANSFER REQUEST {'*'*10}")
        print(f"Peer '{sender}' wants to download: {filename}")
        print(f"Type 'accept' to allow or 'deny' to cancel.")
        print(f"{self.app.user_id} > ", end="", flush=True)

    def execute_approved_transfer(self, sender, filename):
        """Finalizes the transfer once the user types 'accept'."""
        session = self.app.active_sessions.get(sender)
        if not session:
            self.app.log("security", "Session lost during approval.")
            return

        try:
            # Check if file exists in shared, if not, try to export it from vault
            if filename not in self.app.disk_store.list_shared_files():
                self.app.disk_store.export_from_vault_to_shared(filename)
            
            file_data = self.app.disk_store.get_shared_file_content(filename)
            file_hash = hashlib.sha256(file_data).hexdigest()
            signature = self.app.auth_manager.sign(file_hash.encode())

            encryptor = session["encryptor"]
            encrypted_file = encryptor.encrypt(file_data)

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
                self.app.log("transfer", f"Successfully sent '{filename}' to {sender}.")
        except Exception as e:
            self.app.log("error", f"Transfer execution failed: {e}")

    def handle_transfer_accept(self, sender, payload):
        """Receives, verifies, and saves the file."""
        filename = payload.get("filename")
        encoded_data = payload.get("data")
        received_hash = payload.get("sha256")
        encoded_sig = payload.get("signature")
    
        session = self.app.active_sessions.get(sender)
        if not session:
            self.app.log("security", f"DENIED: No secure session with {sender}.")
            return

        try:
            peer_pub_key = session["peer_identity"]
            signature = base64.b64decode(encoded_sig)
        
            if not self.app.auth_manager.verify_signature(peer_pub_key, signature, received_hash.encode()):
                self.app.log("security", f"CRITICAL: Signature mismatch on '{filename}'!")
                return

            encryptor = session["encryptor"]
            encrypted_blob = base64.b64decode(encoded_data)
            decrypted_data = encryptor.decrypt(encrypted_blob)
        
            if decrypted_data:
                actual_hash = hashlib.sha256(decrypted_data).hexdigest()
                if actual_hash != received_hash:
                    self.app.log("security", f"INTEGRITY FAILURE: Hash mismatch for '{filename}'!")
                    return

                if self.app.disk_store.save_to_vault(filename, decrypted_data):
                    (self.app.disk_store.shared_dir / filename).write_bytes(decrypted_data)
                    self.app.log("file", f"Verified & Received '{filename}' from {sender}.")
            else:
                self.app.log("security", "Decryption failed.")
        except Exception as e:
            self.app.log("error", f"Processing failed: {e}")
        
        print(f"{self.app.user_id} > ", end="", flush=True)

    def handle_transfer_reject(self, sender, payload):
        filename = payload.get("filename")
        self.app.log("transfer", f"Peer {sender} declined the transfer of '{filename}'.")
        print(f"{self.app.user_id} > ", end="", flush=True)

    # --- Discovery & Maintenance ---

    def handle_peer_left(self, sender, payload=None):
        self.app.active_sessions.pop(sender, None)
        if hasattr(self.app, "discovery"):
            self.app.discovery.peers.pop(sender, None)
        self.app.log("network", f"Peer {sender} disconnected.")
        print(f"{self.app.user_id} > ", end="", flush=True)

    def handle_redundancy_query(self, sender, payload):
        filename = payload.get("filename")
        if filename in self.app.disk_store.list_shared_files():
            peer = self.app.discovery.peers.get(sender)
            if peer:
                self.app.network.send_message(peer['ip'], peer['port'], {
                    "type": "REDUNDANCY_OFFER",
                    "sender": self.app.user_id,
                    "payload": {"filename": filename}
                })

    def initiate_key_migration(self):
        # Delegate to rotate_identity which uses the correct AuthManager API
        # and the field names Java expects ("new_identity_key" / "signature")
        self.rotate_identity()

    def process_key_migration(self, sender, payload):
        """
        Processes an incoming identity rotation from a peer.
        Verifies the Proof of Continuity (new key signed by old key).
        """
        try:
            new_key_bytes = base64.b64decode(payload.get("new_identity_key"))
            signature = base64.b64decode(payload.get("signature"))
            
            # 1. Get the OLD public key we have stored for this peer
            session = self.app.active_sessions.get(sender)
            if not session:
                self.app.log("security", f"Migration from {sender} ignored: No active session.")
                return
            
            old_pub_key = session["peer_identity"]

            # 2. Verify: Did the OLD key sign the NEW key?
            if self.app.auth_manager.verify_signature(old_pub_key, signature, new_key_bytes):
                # 3. Update the session with the new identity
                session["peer_identity"] = new_key_bytes
                # Also update discovery so future handshakes use the new key
                if sender in self.app.discovery.peers:
                    self.app.discovery.peers[sender]["public_key"] = base64.b64encode(new_key_bytes).decode()
                
                self.app.log("security", f"KEY MIGRATION SUCCESS: {sender} has updated their identity.")
            else:
                self.app.log("security", f"CRITICAL: Forged migration attempt from {sender}!")
                self.app.active_sessions.pop(sender, None)
        except Exception as e:
            self.app.log("error", f"Migration processing failed: {e}")
    
    def rotate_identity(self):
        try:
            # 1. Generate new keys and proof-of-continuity signature
            old_pub, new_pub, sig = self.app.auth_manager.migrate_identity()

            # 2. Build message as a dict so json.dumps handles encoding cleanly
            message = {
                "type": "KEY_MIGRATION_NOTIFY",
                "sender": self.app.user_id,
                "payload": {
                    "new_identity_key": base64.b64encode(new_pub).decode(),
                    "signature": base64.b64encode(sig).decode()
                }
            }

            # 3. Broadcast to all active peers
            for peer_id, peer_info in self.app.discovery.peers.items():
                self.app.network.send_message(peer_info['ip'], peer_info['port'], message)

            self.app.log("security", "New identity generated and broadcasted to active sessions.")
        except Exception as e:
            self.app.log("error", f"Migration broadcast failed: {e}")