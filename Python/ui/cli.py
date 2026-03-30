import base64
import os
import time
from pathlib import Path
from typing import List, Optional

class AppCLI:
    """
    Command Line Interface for the Secure P2P application.
    Translates user input into logic calls and network broadcasts.
    """
    
    def __init__(self, app):
        self.app = app
        self.commands = {
            "help":     {"func": self.show_help,      "desc": "Show all available commands"},
            "list":     {"func": self.cmd_list,       "desc": "List discovered network peers (mDNS)"},
            "connect":  {"func": self.cmd_connect,    "desc": "Establish secure session <UserID>"},
            "chat":     {"func": self.cmd_chat,       "desc": "Send an encrypted message <UserID>"},
            "vault":    {"func": self.cmd_vault,      "desc": "List locally secured files"},
            "ingest":   {"func": self.cmd_ingest,     "desc": "Encrypt a local file into Vault <path>"},
            "uningest": {"func": self.cmd_uningest,   "desc": "Remove a file from Vault <filename>"},
            "fetch":    {"func": self.cmd_fetch,      "desc": "Request a list of shared files <UserID>"},
            "request":  {"func": self.cmd_request,    "desc": "Download a file from a peer <UserID> <filename>"},
            "send":     {"func": self.cmd_send,       "desc": "Propose a file transfer <UserID> <filename>"},
            "find":     {"func": self.cmd_find,       "desc": "Search for redundant file copies <filename>"},
            "migrate":  {"func": self.cmd_migrate,    "desc": "Migrate identity keys (broadcast to peers)"},
            "accept":   {"func": self.cmd_accept,     "desc": "Accept a pending file transfer"},
            "deny":     {"func": self.cmd_deny,       "desc": "Deny a pending file transfer"},
            "exit":     {"func": self.app.shutdown,   "desc": "Safely shut down the application"}
        }

    def print_banner(self):
        """Displays the application header on startup."""
        banner = f" SECURE P2P: {self.app.user_id} "
        print(f"\n{'='*50}\n{banner:^50}\n{'='*50}")
        self.app.log("system", "Vault Unlocked. System Ready.")

    def show_help(self, *args):
        """Prints the command table."""
        print(f"\n{'COMMAND':<12} | {'DESCRIPTION'}")
        print("-" * 52)
        for cmd, info in sorted(self.commands.items()):
            print(f"{cmd:<12} | {info['desc']}")

    def _require_session(self, target: str) -> bool:
        """Centralized security gate to ensure a cryptographic tunnel exists."""
        if target not in self.app.active_sessions:
            self.app.log("error", f"Access Denied: No secure session with {target}.")
            return False
        return True

    # --- Discovery & Connection ---

    def cmd_list(self, *args):
        """Lists peers found via mDNS and their session status."""
        peers = self.app.discovery.peers
        if not peers:
            return self.app.log("system", "No active peers found on local network.")
        
        print(f"\n--- Discovered Peers ({len(peers)}) ---")
        for name, info in peers.items():
            status = "SECURE-SESSION" if name in self.app.active_sessions else "No-Session"
            print(f" > {name:<15} [{info['ip']}:{info['port']}] Status: {status}")

    def cmd_connect(self, *args):
        """Triggers the Diffie-Hellman handshake with a peer."""
        target = args[0] if args else input("Connect to (UserID): ").strip()
        peer = self.app.discovery.peers.get(target)
        
        if peer:
            msg = self.app.logic.initiate_handshake(target)
            if self.app.network.send_message(peer['ip'], peer['port'], msg):
                self.app.log("security", f"Handshake dispatched to {target}...")
        else:
            self.app.log("error", f"Peer '{target}' not found. Check 'list'.")

    # --- Communication ---

    def cmd_chat(self, *args):
        """Sends an end-to-end encrypted message."""
        target = args[0] if args else input("Recipient: ").strip()
        if not target or not self._require_session(target): return

        text = input(f"Message for {target}: ").strip()
        if not text: return

        try:
            encryptor = self.app.active_sessions[target]["encryptor"]
            encrypted_blob = encryptor.encrypt(text.encode())
            peer = self.app.discovery.peers.get(target)
            
            self.app.network.send_message(peer['ip'], peer['port'], {
                "type": "CHAT_MESSAGE",
                "sender": self.app.user_id,
                "payload": base64.b64encode(encrypted_blob).decode()
            })
            self.app.log("system", f"Message sent to {target}.")
        except Exception as e:
            self.app.log("error", f"Encryption failed: {e}")

    # --- Storage Management ---

    def cmd_vault(self, *args):
        """Lists files currently in the local encrypted vault."""
        files = self.app.disk_store.list_encrypted_files()
        if not files:
            self.app.log("system", "Vault is empty.")
        else:
            print(f"\n--- Encrypted Vault ---")
            for f in files: 
                self.app.log("security", f"Locked: {f}")

    def cmd_ingest(self, *args):
        """Encrypts a file from the host system into the application vault."""
        path = args[0] if args else input("File path to ingest: ").strip()
        if path: 
            self.app.disk_store.ingest_file(path)

    def cmd_uningest(self, *args):
        """Deletes a file from the vault and the shared directory."""
        filename = args[0] if args else input("Filename to remove: ").strip()
        if filename:
            confirm = input(f"Confirm deletion of '{filename}'? (y/n): ").lower()
            if confirm == 'y':
                self.app.disk_store.uningest_file(filename)

    # --- File Sharing & Redundancy ---

    def cmd_fetch(self, *args):
        """Requests the public file list from a secure peer."""
        target = args[0] if args else input("Fetch file list from (UserID): ").strip()
        if target and self._require_session(target):
            self.app.logic.request_file_list(target)

    def cmd_request(self, *args):
        """Downloads a specific file from a peer."""
        target = args[0] if args else input("Request from: ").strip()
        filename = args[1] if len(args) > 1 else input("Filename: ").strip()
        
        if target and filename and self._require_session(target):
            self.app.logic.initiate_file_request(target, filename)

    def cmd_send(self, *args):
        """Proposes to 'push' a file to another peer."""
        target = args[0] if args else input("Recipient UserID: ").strip()
        filename = args[1] if len(args) > 1 else input("Filename from Vault: ").strip()

        if not target or not filename or not self._require_session(target): 
            return

        if filename not in self.app.disk_store.list_encrypted_files():
            return self.app.log("error", f"'{filename}' not found in local Vault.")

        self.app.last_pushed_file = filename
        peer = self.app.discovery.peers.get(target)
        if peer:
            self.app.network.send_message(peer['ip'], peer['port'], {
                "type": "PUSH_PROPOSAL", 
                "sender": self.app.user_id,
                "payload": {"filename": filename}
            })
            self.app.log("transfer", f"Push proposal for '{filename}' sent to {target}.")

    def cmd_find(self, *args):
        """Broadcasts a search for redundant copies of a file across all secure peers."""
        filename = args[0] if args else input("Search for filename: ").strip()
        if not filename: return

        active_targets = [t for t in self.app.active_sessions.keys()]
        if not active_targets:
            return self.app.log("error", "No active secure sessions to search.")

        self.app.log("system", f"Searching for '{filename}' across {len(active_targets)} peers...")
        for target in active_targets:
            peer = self.app.discovery.peers.get(target)
            if peer:
                self.app.network.send_message(peer['ip'], peer['port'], {
                    "type": "REDUNDANCY_QUERY",
                    "sender": self.app.user_id,
                    "payload": {"filename": filename, "query_id": os.urandom(4).hex()}
                })

    # --- Identity & Consent ---

    def cmd_migrate(self, *args):
        """Forces an identity rotation and notifies all peers to update their trust records."""
        self.app.logic.rotate_identity()

    def cmd_accept(self, *args):
        """Approves a pending incoming transfer or push proposal."""
        pending = getattr(self.app, "pending_transfer", None)
        if not pending:
            return self.app.log("error", "No pending transfer requests.")
        
        sender = pending["sender"]
        filename = pending["filename"]
        
        if pending["type"] == "PUSH":
            peer = self.app.discovery.peers.get(sender)
            if peer:
                self.app.network.send_message(peer['ip'], peer['port'], {
                    "type": "TRANSFER_REQUEST", 
                    "sender": self.app.user_id, 
                    "payload": {"filename": filename}
                })
                self.app.log("transfer", f"Accepted push. Requesting '{filename}'...")
        else:
            self.app.logic.execute_approved_transfer(sender, filename)
            
        self.app.pending_transfer = None
        self.app.awaiting_consent = False

    def cmd_deny(self, *args):
        """Rejects a pending incoming transfer proposal."""
        pending = getattr(self.app, "pending_transfer", None)
        if pending:
            sender = pending["sender"]
            peer = self.app.discovery.peers.get(sender)
            if peer:
                self.app.network.send_message(peer['ip'], peer['port'], {
                    "type": "TRANSFER_REJECT", 
                    "sender": self.app.user_id, 
                    "payload": {"filename": pending["filename"]}
                })
        self.app.pending_transfer = None
        self.app.awaiting_consent = False
        self.app.log("system", "Transfer request denied.")

    def run_loop(self):
        """Main CLI input loop."""
        self.print_banner()
        while True:
            try:
                if getattr(self.app, "awaiting_consent", False):
                    time.sleep(0.2)
                    continue

                user_input = input(f"\n{self.app.user_id} > ").strip().split()
                if not user_input: continue
                
                cmd_name, args = user_input[0].lower(), user_input[1:]
                
                if cmd_name in self.commands:
                    self.commands[cmd_name]["func"](*args)
                    if cmd_name == "exit": break
                else:
                    self.app.log("error", f"Unknown command: '{cmd_name}'. Type 'help' for list.")
                    
            except (EOFError, KeyboardInterrupt):
                self.app.shutdown()
                break