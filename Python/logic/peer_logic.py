import os
import json
import base64

class PeerLogic:
    def __init__(self, app):
        self.app = app
        self.peers = {}  # Stores session keys and addr: {sender: {"key": k, "addr": a}}
        self.active_transfers = {} # Tracks chunks for incoming/outgoing files

    # --- Auth & Key Exchange ---
    def process_handshake_init(self, sender, payload, addr):
        """
        Req 2: Verify identity and establish a session key.
        Payload usually contains the sender's Public Key.
        """
        public_key = payload.get("public_key")
        self.app.log("security", f"Handshake started with {sender} at {addr}")
        
        # 1. Store peer info
        self.peers[sender] = {"addr": addr, "pub_key": public_key}
        
        # 2. Respond with our own key (Simplified logic)
        response_payload = {"status": "accepted", "my_pub_key": "LOCAL_PUB_KEY"}
        self.app.network.send(sender, "HANDSHAKE_RESPONSE", response_payload)

    def process_handshake_response(self, sender, payload):
        self.app.log("security", f"Handshake completed with {sender}.")
        self.app.update_peer_list(sender, status="Secure")

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
        """Req 7: Display encrypted/decrypted chat."""
        message = payload.get("text")
        self.app.display_chat(sender, message)

    # --- Internal Helpers ---
    def _finalize_file(self, filename):
        with open(f"./downloads/{filename}", "wb") as f:
            for chunk in self.active_transfers[filename]:
                f.write(chunk)
        del self.active_transfers[filename]
        self.app.log("file", f"Successfully downloaded {filename}")



    # TEST
    def initiate_handshake(self, target_id):
        """
        Requirement 8: Prepare a Perfect Forward Secrecy (PFS) Handshake.
        Generates ephemeral keys to ensure past sessions remain secure 
        even if long-term keys are compromised.
        """
        # 1. Get our long-term public identity from AuthManager
        my_identity_pub = self.app.auth_manager.get_public_key()
        
        # 2. Generate an ephemeral (temporary) key for this specific session
        # This is the 'Forward Secrecy' part.
        ephemeral_key = self.app.auth_manager.generate_ephemeral_share()

        # 3. Construct the protocol message
        return {
            "type": "HANDSHAKE_INIT",
            "sender": self.app.user_id,
            "payload": {
                "identity_key": base64.b64encode(my_identity_pub).decode(),
                "ephemeral_share": base64.b64encode(ephemeral_key).decode(),
                "timestamp": self.app.get_timestamp()
            }
        }
    
    def handle_redundancy_offer(self, sender, payload):
        """Requirement 5: Process a peer's offer to host a file."""
        filename = payload.get("filename")
        print(f"\n[+] Redundancy Found: {sender} can provide '{filename}'.")