import os
import json
import base64

class PeerLogic:
    def __init__(self, app):
        self.app = app
        self.peers = {} 
        self.active_transfers = {}

    # --- Auth & Key Exchange ---
    def process_handshake_init(self, sender, payload, addr):
        """Requirement 2 & 8: Handles incoming handshake with Mutual Auth."""
        try:
            # 1. Extract keys and signature
            peer_id_pub = base64.b64decode(payload.get("identity_key"))
            peer_ephemeral_pub = base64.b64decode(payload.get("ephemeral_share"))
            peer_signature = base64.b64decode(payload.get("signature"))

            # 2. MUTUAL AUTH: Verify the peer actually owns the identity they claim
            if not self.app.auth_manager.verify_signature(peer_id_pub, peer_signature, peer_ephemeral_pub):
                self.app.log("security", f"Critical: Handshake signature verification failed for {sender}!")
                return

            # 3. Generate our session response
            local_priv, local_pub = self.app.auth_manager.generate_ephemeral_pair()
            
            # 4. Derive the session key
            session_key = self.app.auth_manager.derive_shared_secret(peer_ephemeral_pub, local_priv)
            encryptor = self.app.auth_manager.create_encryptor(session_key)

            # 5. Store the secure session
            self.app.active_sessions[sender] = {
                "status": "SECURE-SESSION",
                "encryptor": encryptor,
                "peer_identity": peer_id_pub # Store their verified ID
            }

            # 6. Sign our ephemeral key and respond
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
            self.app.log("error", f"Handshake Init Failed: {str(e)}")

    def process_handshake_response(self, sender, payload):
        """Requirement 2 & 8: Finalize handshake with signature check."""
        try:
            peer_ephemeral_pub = base64.b64decode(payload.get("ephemeral_key"))
            peer_signature = base64.b64decode(payload.get("signature"))
            peer_id_pub = base64.b64decode(payload.get("identity_key"))

            # 1. Verify their response signature
            if not self.app.auth_manager.verify_signature(peer_id_pub, peer_signature, peer_ephemeral_pub):
                self.app.log("security", f"Security Alert: {sender} provided an invalid signature!")
                return

            # 2. Complete the key exchange
            local_priv = self.app.auth_manager.pending_handshakes.get(sender)
            if not local_priv:
                self.app.log("error", "Received unexpected handshake response.")
                return

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
            self.app.log("error", f"Handshake Response Failed: {str(e)}")

    def initiate_handshake(self, target_id):
        try:
            my_id_pub = self.app.auth_manager.get_public_key()
            
            if my_id_pub == b"ERROR_NO_KEY" or my_id_pub == b"ERROR_KEY":
                self.app.log("error", "Handshake aborted: Identity key is missing.")
                return None

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
        """Bob receives this and updates Alice's identity in his registry."""
        old_pub = base64.b64decode(payload.get("old_identity"))
        new_pub = base64.b64decode(payload.get("new_identity"))
        sig = base64.b64decode(payload.get("migration_sig"))

        try:
            old_pub_obj = ed25519.Ed25519PublicKey.from_public_bytes(old_pub)
            old_pub_obj.verify(sig, new_pub)
            
            self.app.log("security", f"VERIFIED: {sender} has migrated to a new identity key.")
            
            if sender in self.app.active_sessions:
                self.app.active_sessions[sender]["peer_identity"] = new_pub
                self.app.log("system", f"Re-calculating secure channel with {sender}...")
                self.initiate_handshake(sender)
                
        except Exception:
            self.app.log("error", f"REJECTED: Malicious key migration attempt from {sender}!")

    # --- Communication ---
    def process_chat_message(self, sender, payload):
        """Requirement 7: Decrypt and display chat message cleanly."""
        session = self.app.active_sessions.get(sender)
        if not session or "encryptor" not in session:
            return

        try:
            # 1. Decode and Decrypt
            encrypted_blob = base64.b64decode(payload)
            decrypted_bytes = session["encryptor"].decrypt(encrypted_blob)
            
            if decrypted_bytes:
                message_text = decrypted_bytes.decode('utf-8')
                
                print(f"\r\033[K[ {sender} ]: {message_text}")
                
                # 3. Restore the prompt so the user knows they can still type
                print(f"{self.app.user_id} > ", end="", flush=True)
                
        except Exception:
            self.app.log("error", "Failed to decrypt incoming message.")

    def request_file_list(self, target_id):
        peer = self.app.discovery.peers.get(target_id)
        if not peer:
            self.app.log("error", f"Peer {target_id} not found.")
            return

        self.app.network.send_message(peer['ip'], peer['port'], {
            "type": "FILE_LIST_REQUEST",
            "sender": self.app.user_id,
            "payload": {}
        })
        self.app.log("system", f"Requested file list from {target_id}...")

    def handle_list_request(self, sender, payload=None):
        """Replies automatically with shared files (Requirement 4)."""
        files = self.app.disk_store.list_shared_files()
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
            print(f"\n--- {sender} has no shared files ---")
        else:
            print(f"\n--- Files available from {sender} ({len(files)}) ---")
            for f in files:
                print(f"  > {f}")
        
        print(f"\n{self.app.user_id} > ", end="", flush=True)

    # --- Internal Helpers ---
    def _finalize_file(self, filename):
        with open(f"./downloads/{filename}", "wb") as f:
            for chunk in self.active_transfers[filename]:
                f.write(chunk)
        del self.active_transfers[filename]
        self.app.log("file", f"Successfully downloaded {filename}")
    
    def handle_redundancy_offer(self, sender, payload):
        """Requirement 5: Process a peer's offer to host a file."""
        filename = payload.get("filename")
        print(f"\n[+] Redundancy Found: {sender} can provide '{filename}'.")

    def handle_peer_left(self, sender, payload=None):
        if sender in self.peers:
            del self.peers[sender]

        if sender in self.app.active_sessions:
            del self.app.active_sessions[sender]

        if hasattr(self.app, "discovery") and hasattr(self.app.discovery, "peers"):
            if sender in self.app.discovery.peers:
                del self.app.discovery.peers[sender]

        self.app.log("network", f"{sender} left the network.")