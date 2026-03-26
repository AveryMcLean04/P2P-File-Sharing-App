import os
import json
import base64

class PeerLogic:
    def __init__(self, app):
        self.app = app
        self.peers = {} 
        self.active_transfers = {}

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
        """Requirement 8: Construct the signed HANDSHAKE_INIT."""
        local_priv, local_pub = self.app.auth_manager.generate_ephemeral_pair()
        self.app.auth_manager.pending_handshakes[target_id] = local_priv

        my_id_pub = self.app.auth_manager.get_public_key()
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

    # --- Auth & Key Exchange ---
    # def process_handshake_init(self, sender, payload, addr):
    #     """Handles incoming handshake from Alice."""
    #     peer_ephemeral_bytes = base64.b64decode(payload.get("ephemeral_share"))
        
    #     # 1. Generate our own local session pair
    #     local_priv, local_pub = self.app.auth_manager.generate_ephemeral_pair()
        
    #     # 2. Derive the key and create the encryptor object
    #     session_key = self.app.auth_manager.derive_shared_secret(peer_ephemeral_bytes, local_priv)
    #     encryptor = self.app.auth_manager.create_encryptor(session_key)

    #     # 3. CRITICAL: Store in active_sessions for the CLI
    #     self.app.active_sessions[sender] = {
    #         "status": "SECURE-SESSION",
    #         "encryptor": encryptor # cmd_chat looks for this!
    #     }

    #     # 4. Respond to Alice
    #     response = {
    #         "ephemeral_key": base64.b64encode(local_pub).decode(),
    #         "signature": base64.b64encode(self.app.auth_manager.sign(local_pub)).decode()
    #     }
        
    #     peer = self.app.discovery.peers.get(sender)
    #     self.app.network.send_message(peer['ip'], peer['port'], {
    #         "type": "HANDSHAKE_RESPONSE", "sender": self.app.user_id, "payload": response
    #     })

    # def process_handshake_response(self, sender, payload):
    #     """Handles the reply when WE started the handshake."""
    #     peer_ephemeral_bytes = base64.b64decode(payload.get("ephemeral_key"))
    
    #     # Alice looks for the key she saved in Step 1
    #     local_priv = self.app.auth_manager.pending_handshakes.get(sender)
    
    #     if not local_priv:
    #         self.app.log("error", f"Security Alert: Received handshake response from {sender} but no record of initiating one.")
    #         return

    #     # Finish the math
    #     session_key = self.app.auth_manager.derive_shared_secret(peer_ephemeral_bytes, local_priv)
    #     encryptor = self.app.auth_manager.create_encryptor(session_key)

    #     # Now Alice is also SECURE
    #     self.app.active_sessions[sender] = {
    #         "status": "SECURE-SESSION",
    #         "encryptor": encryptor
    #     }
    
    #     # Clean up the memory
    #     del self.app.auth_manager.pending_handshakes[sender]
    #     self.app.log("security", f"Secure session with {sender} finalized.")

    # --- File Management ---
    def handle_list_request(self, sender):
        """Req 3: Share a list of non-private files."""
        shared_files = [f for f in os.listdir("./shared") if not f.startswith(".")]
        self.app.network.send(sender, "FILE_LIST_RESPONSE", {"files": shared_files})

    def handle_transfer_request(self, sender, payload):
        """Req 4: User prompted to accept/reject incoming file."""
        filename = payload.get("filename")
        filesize = payload.get("size")
        
        # Trigger UI prompt
        if self.app.prompt_user(f"Accept {filename} ({filesize} bytes) from {sender}?"):
            self.app.network.send(sender, "TRANSFER_ACCEPT", {"filename": filename})
        else:
            self.app.network.send(sender, "TRANSFER_REJECT", {"filename": filename})

    def process_file_transfer(self, sender, payload):
        """Req 4 & 5: Reassemble file chunks."""
        filename = payload.get("filename")
        chunk_data = payload.get("data")
        is_last = payload.get("eof", False)

        if filename not in self.active_transfers:
            self.active_transfers[filename] = []

        self.active_transfers[filename].append(base64.b64decode(chunk_data))

        if is_last:
            self._finalize_file(filename)

    # --- Redundancy & Search ---
    def handle_redundancy_query(self, sender, payload):
        """Req 5: Check if we have space to host a backup for a peer."""
        file_hash = payload.get("hash")
        # Logic to check disk quota
        if self.app.has_space():
            self.app.network.send(sender, "REDUNDANCY_OFFER", {"hash": file_hash})

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
                
                # 2. CLEAN PRINTING LOGIC
                # \r moves cursor to start, \033[K clears the line
                print(f"\r\033[K[ {sender} ]: {message_text}")
                
                # 3. Restore the prompt so the user knows they can still type
                print(f"{self.app.user_id} > ", end="", flush=True)
                
        except Exception:
            self.app.log("error", "Failed to decrypt incoming message.")

    # --- Internal Helpers ---
    def _finalize_file(self, filename):
        with open(f"./downloads/{filename}", "wb") as f:
            for chunk in self.active_transfers[filename]:
                f.write(chunk)
        del self.active_transfers[filename]
        self.app.log("file", f"Successfully downloaded {filename}")



    # TEST
    # def initiate_handshake(self, target_id):
    #     """Requirement 8: Prepare PFS Handshake and SAVE the local private key."""
    #     # 1. Generate the temporary session pair
    #     local_priv, local_pub = self.app.auth_manager.generate_ephemeral_pair()

    #     # 2. CRITICAL: Save the private key so we can finish the math later
    #     # This is what Alice was missing!
    #     self.app.auth_manager.pending_handshakes[target_id] = local_priv

    #     # 3. Get our long-term public identity
    #     my_identity_pub = self.app.auth_manager.get_public_key()

    #     signature = self.app.auth_manager.sign(local_pub)

    #     # 4. Construct the protocol message
    #     return {
    #         "type": "HANDSHAKE_INIT",
    #         "sender": self.app.user_id,
    #         "payload": {
    #             "identity_key": base64.b64encode(my_identity_pub).decode(),
    #             "ephemeral_share": base64.b64encode(local_pub).decode(),
    #             "signature": base64.b64encode(signature).decode(),
    #             "timestamp": self.app.get_timestamp()
    #         }
    #     }
    # def initiate_handshake(self, target_id):
    #     """
    #     Requirement 8: Prepare a Perfect Forward Secrecy (PFS) Handshake.
    #     Generates ephemeral keys to ensure past sessions remain secure 
    #     even if long-term keys are compromised.
    #     """
    #     # 1. Get our long-term public identity from AuthManager
    #     my_identity_pub = self.app.auth_manager.get_public_key()
        
    #     # 2. Generate an ephemeral (temporary) key for this specific session
    #     # This is the 'Forward Secrecy' part.
    #     ephemeral_key = self.app.auth_manager.generate_ephemeral_share()

    #     # 3. Construct the protocol message
    #     return {
    #         "type": "HANDSHAKE_INIT",
    #         "sender": self.app.user_id,
    #         "payload": {
    #             "identity_key": base64.b64encode(my_identity_pub).decode(),
    #             "ephemeral_share": base64.b64encode(ephemeral_key).decode(),
    #             "timestamp": self.app.get_timestamp()
    #         }
    #     }
    
    def handle_redundancy_offer(self, sender, payload):
        """Requirement 5: Process a peer's offer to host a file."""
        filename = payload.get("filename")
        print(f"\n[+] Redundancy Found: {sender} can provide '{filename}'.")

    def handle_peer_left(self, sender, payload=None):
        # Remove from local session tracker
        if sender in self.peers:
            del self.peers[sender]

        # Remove from app session tracker
        if sender in self.app.active_sessions:
            del self.app.active_sessions[sender]

        # Remove from discovery registry too, if you keep peers there
        if hasattr(self.app, "discovery") and hasattr(self.app.discovery, "peers"):
            if sender in self.app.discovery.peers:
                del self.app.discovery.peers[sender]

        self.app.log("network", f"{sender} left the network.")