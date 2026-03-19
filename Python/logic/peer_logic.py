import base64
import hashlib
import time
from crypto.session import SessionManager
from crypto.encryption import FileEncryptor

class PeerLogic:
    def __init__(self, app):
        """
        The 'Brain' of the application. 
        Handles all protocol rules and command executions.
        """
        self.app = app

    # --- [REQ #2] AUTHENTICATION & HANDSHAKE ---

    def process_handshake_init(self, sender, payload, addr):
        session = SessionManager()
        try:
            # 1. Extract and Decode incoming data
            peer_ephemeral = base64.b64decode(payload["ephemeral_key"])
            peer_sig = base64.b64decode(payload["signature"])

            # 2. Retrieve the actual Public Key for the sender
            peers = self.app.discovery.get_active_peers()
            peer_info = peers.get(sender)

            if not peer_info or "public_key" not in peer_info:
                self.app.log("security", f"AUTH FAILURE: No public key found for {sender}")
                return

            # Convert the stored public key string/base64 to bytes
            peer_static_pub_bytes = base64.b64decode(peer_info["public_key"])

            # 3. Verify the signature using the BYTES, not the sender's name string
            if not self.app.key_mgr.verify_peer_signature(peer_static_pub_bytes, peer_ephemeral, peer_sig):
                self.app.log("security", f"AUTH FAILURE: {sender} signature invalid!")
                return

            # 4. Success - Derive shared secret and set up encryption
            shared_key = session.derive_shared_secret(peer_ephemeral)
            self.app.active_sessions[sender] = {"encryptor": FileEncryptor(shared_key)}
            
            # 5. Prepare Response (Sign our own ephemeral key)
            my_ephemeral = session.get_public_bytes()
            my_signature = self.app.key_mgr.sign_data(my_ephemeral)

            response = {
                "type": "HANDSHAKE_RESPONSE", 
                "sender": self.app.config.user_id,
                "payload": {
                    "ephemeral_key": base64.b64encode(my_ephemeral).decode('utf-8'),
                    "signature": base64.b64encode(my_signature).decode('utf-8')
                }
            }
            
            # 6. Send back to the peer
            peer_port = peer_info.get('port', addr[1])
            self.app.network.send_message(addr[0], peer_port, response)
            self.app.log("security", f"Authenticated tunnel established with {sender}")

        except Exception as e:
            self.app.log("error", f"Handshake init failed: {e}")

    def process_handshake_response(self, sender, payload):
        # Only process if we are actually expecting a response from this sender
        if sender in self.app.active_sessions and "session" in self.app.active_sessions[sender]:
            try:
                session = self.app.active_sessions[sender]["session"]
                peer_ephemeral = base64.b64decode(payload["ephemeral_key"])
                peer_sig = base64.b64decode(payload["signature"])

                # 1. Retrieve the Peer's Public Key
                peers = self.app.discovery.get_active_peers()
                peer_info = peers.get(sender)
                
                if not peer_info or "public_key" not in peer_info:
                    self.app.log("security", f"AUTH FAILURE: Registry missing key for {sender}")
                    return

                peer_static_pub_bytes = base64.b64decode(peer_info["public_key"])

                # 2. Verify Identity
                if not self.app.key_mgr.verify_peer_signature(peer_static_pub_bytes, peer_ephemeral, peer_sig):
                    self.app.log("security", f"AUTH FAILURE: {sender} response signature check failed!")
                    # Clean up the failed session attempt
                    del self.app.active_sessions[sender]
                    return

                # 3. Finalize Encryption
                shared_key = session.derive_shared_secret(peer_ephemeral)
                self.app.active_sessions[sender] = {"encryptor": FileEncryptor(shared_key)}
                self.app.log("security", f"Authenticated tunnel finalized with {sender}")

            except Exception as e:
                self.app.log("error", f"Response auth failed: {e}")
                if sender in self.app.active_sessions:
                    del self.app.active_sessions[sender]

    # --- [REQ #3, #4, #5] FILE OPERATIONS ---

    def handle_list_request(self, sender):
        file_info = {}
        for f in self.app.shared_path.iterdir():
            if f.is_file():
                file_info[f.name] = hashlib.sha256(f.read_bytes()).hexdigest()
        
        peer = self.app.discovery.get_active_peers().get(sender)
        if peer:
            self.app.network.send_message(peer['address'], peer['port'], {
                "type": "FILE_LIST_RESPONSE", "sender": self.app.config.user_id,
                "payload": {"files": file_info}
            })

    def process_list_response(self, sender, payload):
        files = payload.get("files", {})
        print(f"\n--- Files available from {sender} ---")
        for name, f_hash in files.items():
            self.app.global_registry[name] = {"original_owner": sender, "hash": f_hash}
            print(f"  - {name} (Hash: {f_hash[:8]}...)")

    def handle_transfer_request(self, sender, payload):
        fname = payload.get("filename")
        print(f"\n[!] ALERT: {sender} wants to send '{fname}'. Accept? (y/n)")
        choice = input(f"{self.app.config.user_id} > ").strip().lower()

        peer = self.app.discovery.get_active_peers().get(sender)
        m_type = "TRANSFER_ACCEPT" if choice == 'y' else "TRANSFER_REJECT"
        
        if peer:
            self.app.network.send_message(peer['address'], peer['port'], {
                "type": m_type, "sender": self.app.config.user_id, "payload": {"filename": fname}
            })

    def handle_transfer_accept(self, sender, payload):
        fname = payload.get("filename")
        file_path = self.app.shared_path / fname
        if sender not in self.app.active_sessions: return
        
        encryptor = self.app.active_sessions[sender]["encryptor"]
        data = file_path.read_bytes()
        nonce, ciphertext = encryptor.encrypt_data(data)
        
        peer = self.app.discovery.get_active_peers().get(sender)
        if peer:
            self.app.network.send_message(peer['address'], peer['port'], {
                "type": "FILE_DATA_PACKET", "sender": self.app.config.user_id,
                "payload": {
                    "filename": fname,
                    "nonce": base64.b64encode(nonce).decode('utf-8'),
                    "data": base64.b64encode(ciphertext).decode('utf-8')
                }
            })
            self.app.log("success", f"File '{fname}' dispatched to {sender}.")

    def process_file_transfer(self, sender, payload):
        try:
            encryptor = self.app.active_sessions[sender]["encryptor"]
            nonce = base64.b64decode(payload["nonce"])
            ciphertext = base64.b64decode(payload["data"])
            decrypted = encryptor.decrypt_data(nonce, ciphertext)
            
            fname = payload["filename"]
            actual_hash = hashlib.sha256(decrypted).hexdigest()
            registry_entry = self.app.global_registry.get(fname)
            
            if registry_entry and actual_hash != registry_entry["hash"]:
                self.app.log("alert", f"TAMPERING DETECTED: {fname} hash mismatch!")
                return

            save_path = str(self.app.data_path / "received")
            self.app.storage.save_file(fname, decrypted, save_path)
            self.app.log("success", f"Received and verified {fname} (Saved securely).")
        except Exception as e:
            self.app.log("error", f"Transfer failure: {e}")

    # --- [REQ #5] REDUNDANCY & SEARCH ---

    def handle_redundancy_query(self, sender, payload):
        fname, req_hash = payload["filename"], payload["hash"]
        paths = [self.app.shared_path / fname, self.app.data_path / "received" / fname]
        
        for path in paths:
            if path.exists() and hashlib.sha256(path.read_bytes()).hexdigest() == req_hash:
                peer = self.app.discovery.get_active_peers().get(sender)
                if peer:
                    self.app.network.send_message(peer['address'], peer['port'], {
                        "type": "REDUNDANCY_OFFER", "sender": self.app.config.user_id,
                        "payload": {"filename": fname}
                    })
                return

    def handle_redundancy_offer(self, sender, payload):
        fname = payload["filename"]
        self.app.log("success", f"Found redundancy! {sender} has a verified copy of '{fname}'.")
        print(f"[!] Use 'connect {sender}' then request the file if needed.")

    # --- CLI COMMAND EXECUTIONS ---

    def cmd_list(self, *args):
        peers = self.app.discovery.get_active_peers()
        if not peers: return print("[-] No peers found.")
        for name, info in peers.items():
            status = "Encrypted-Session" if name in self.app.active_sessions else "No-Session"
            print(f" > {name:<15} [{info['address']}:{info['port']}] {status}")

    def cmd_connect(self, target=None):
        if not target: target = input("Connect to: ")
        peers = self.app.discovery.get_active_peers()
        if target in peers:
            session = SessionManager()
            self.app.active_sessions[target] = {"session": session}
            e_key = session.get_public_bytes()
            sig = self.app.key_mgr.sign_message(e_key)
            
            self.app.network.send_message(peers[target]['address'], peers[target]['port'], {
                "type": "HANDSHAKE_INIT", "sender": self.app.config.user_id,
                "payload": {
                    "ephemeral_key": base64.b64encode(e_key).decode('utf-8'),
                    "signature": base64.b64encode(sig).decode('utf-8')
                }
            })
        else:
            print(f"[-] Peer '{target}' unknown.")

    def cmd_fetch(self, *args):
        target = input("Fetch from: ")
        peers = self.app.discovery.get_active_peers()
        if target in peers:
            self.app.network.send_message(peers[target]['address'], peers[target]['port'], {
                "type": "FILE_LIST_REQUEST", "sender": self.app.config.user_id
            })

    def cmd_send(self, *args):
        target = input("Recipient: ")
        filename = input("Filename to send: ")
        file_path = self.app.shared_path / filename

        if not file_path.exists(): return print("[-] File not found.")
        if target not in self.app.active_sessions: return print("[-] Connect first.")

        peer = self.app.discovery.get_active_peers().get(target)
        if peer:
            self.app.network.send_message(peer['address'], peer['port'], {
                "type": "TRANSFER_REQUEST", "sender": self.app.config.user_id,
                "payload": {"filename": filename, "size": file_path.stat().st_size}
            })

    def cmd_find(self, *args):
        if not args: return print("[-] Specify a filename.")
        fname = args[0]
        if fname not in self.app.global_registry:
            return print(f"[-] No history of '{fname}'. Run 'fetch' on a peer first.")

        target_hash = self.app.global_registry[fname]["hash"]
        for name, info in self.app.discovery.get_active_peers().items():
            self.app.network.send_message(info['address'], info['port'], {
                "type": "REDUNDANCY_QUERY", "sender": self.app.config.user_id,
                "payload": {"filename": fname, "hash": target_hash}
            })

    def cmd_rotate(self, *args):
        self.app.key_mgr.generate_new_keys()
        new_pub = self.app.key_mgr.get_public_key_bytes()
        for peer_name in self.app.active_sessions:
            peer = self.app.discovery.get_active_peers().get(peer_name)
            if peer:
                self.app.network.send_message(peer['address'], peer['port'], {
                    "type": "KEY_MIGRATION", "sender": self.app.config.user_id,
                    "payload": {"new_key": base64.b64encode(new_pub).decode('utf-8')}
                })
        self.app.log("security", "Keys rotated and peers notified.")