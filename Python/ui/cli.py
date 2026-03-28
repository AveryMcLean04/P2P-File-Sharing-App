import base64
import os
from pathlib import Path

class AppCLI:
    def __init__(self, app):
        self.app = app
        self.commands = {
            "help":     {"func": self.show_help,      "desc": "Show all available commands"},
            "list":     {"func": self.cmd_list,       "desc": "List discovered network peers (mDNS)"},
            "connect":  {"func": self.cmd_connect,    "desc": "Establish secure session"},
            "chat":     {"func": self.cmd_chat,       "desc": "Send an encrypted message"},
            "vault":    {"func": self.cmd_vault,      "desc": "List locally secured files"},
            "ingest":   {"func": self.cmd_ingest,     "desc": "Encrypt a local file into Vault"},
            "uningest": {"func": self.cmd_uningest,   "desc": "Remove a file from Vault"},
            "request":  {"func": self.cmd_request, "desc": "Download a file from a peer"},
            "fetch":    {"func": self.cmd_fetch,      "desc": "Request a list of shared files"},
            "send":     {"func": self.cmd_send,       "desc": "Propose a file transfer"},
            "find":     {"func": self.cmd_find,       "desc": "Search for redundant file copies"},
            "migrate":  {"func": self.cmd_migrate,    "desc": "Migrate identity keys"},
            "accept": {"func": self.cmd_accept, "desc": "Accept a pending file transfer"},
            "deny":   {"func": self.cmd_deny,   "desc": "Deny a pending file transfer"},
            "exit":     {"func": self.app.shutdown,   "desc": "Safely shut down the application"}
        }

    def print_banner(self):
        banner = f" SECURE P2P: {self.app.user_id} "
        print(f"\n{'='*50}\n{banner:^50}\n{'='*50}")
        self.app.log("system", "Vault Unlocked. System Ready.")

    def show_help(self, *args):
        print(f"\n{'COMMAND':<12} | {'DESCRIPTION'}")
        print("-" * 52)
        for cmd, info in self.commands.items():
            print(f"{cmd:<12} | {info['desc']}")

    def _require_session(self, target):
        """Centralized security gate for outbound commands."""
        if target not in self.app.active_sessions:
            self.app.log("error", f"Access Denied: No secure session with {target}.")
            return False
        return True

    def cmd_list(self, *args):
        peers = self.app.discovery.peers
        if not peers:
            return self.app.log("system", "No active peers found.")
        
        print(f"\n--- Discovered Peers ({len(peers)}) ---")
        for name, info in peers.items():
            status = "SECURE-SESSION" if name in self.app.active_sessions else "No-Session"
            print(f" > {name:<15} [{info['ip']}:{info['port']}] Status: {status}")

    def cmd_connect(self, *args):
        target = args[0] if args else input("Connect to (UserID): ").strip()
        peer = self.app.discovery.peers.get(target)
        
        if peer:
            msg = self.app.logic.initiate_handshake(target)
            if self.app.network.send_message(peer['ip'], peer['port'], msg):
                self.app.log("security", f"Handshake dispatched to {target}...")
        else:
            self.app.log("error", f"Peer '{target}' not found.")

    def cmd_chat(self, *args):
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

    def cmd_vault(self, *args):
        files = self.app.disk_store.list_encrypted_files()
        if not files:
            self.app.log("system", "Vault is empty.")
        else:
            print(f"\n--- Encrypted Vault ---")
            for f in files: self.app.log("security", f"LOCKED: {f}")

    def cmd_ingest(self, *args):
        path = args[0] if args else input("File path: ").strip()
        if path: self.app.disk_store.ingest_file(path)

    def cmd_uningest(self, *args):
        filename = args[0] if args else input("Filename: ").strip()
        if filename and input(f"Confirm delete '{filename}'? (y/n): ").lower() == 'y':
            self.app.disk_store.uningest_file(filename)

    def cmd_request(self, *args):
        target = args[0] if args else input("Request from: ").strip()
        filename = args[1] if len(args) > 1 else input("Filename: ").strip()
        
        if not target or not filename or not self._require_session(target): return
        
        self.app.logic.initiate_file_request(target, filename)

    def cmd_fetch(self, *args):
        target = args[0] if args else input("Fetch from (UserID): ").strip()

        if target not in self.app.discovery.peers:
            return self.app.log("error", f"Peer '{target}' not discovered yet.")
            
        if self._require_session(target):
            self.app.logic.request_file_list(target)

    def cmd_send(self, *args):
        target = args[0] if args else input("Recipient: ").strip()
        filename = args[1] if len(args) > 1 else input("Filename: ").strip()

        if not target or not filename or not self._require_session(target): 
            return

        if filename not in self.app.disk_store.list_encrypted_files():
            return self.app.log("error", f"'{filename}' is not in your Vault.")

        self.app.last_pushed_file = filename

        peer = self.app.discovery.peers.get(target)
        if peer:
            self.app.network.send_message(peer['ip'], peer['port'], {
                "type": "PUSH_PROPOSAL", 
                "sender": self.app.user_id,
                "payload": {"filename": filename}
            })
            self.app.log("transfer", f"Proposing to send '{filename}' to {target}.")
        else:
            self.app.log("error", f"Peer '{target}' not found in discovery.")

    def cmd_find(self, *args):
        filename = args[0] if args else input("Search filename: ").strip()
        if not filename: return

        active_targets = [t for t in self.app.active_sessions.keys() if t != self.app.user_id]
        if not active_targets:
            return self.app.log("error", "No active secure sessions available for search.")

        for target in active_targets:
            peer = self.app.discovery.peers.get(target)
            if peer:
                self.app.network.send_message(peer['ip'], peer['port'], {
                    "type": "REDUNDANCY_QUERY",
                    "sender": self.app.user_id,
                    "payload": {"filename": filename, "query_id": os.urandom(4).hex()}
                })

    def cmd_migrate(self):
        old_pub, new_pub, sig = self.app.auth_manager.migrate_identity()
        payload = {
            "old_identity": base64.b64encode(old_pub).decode(),
            "new_identity": base64.b64encode(new_pub).decode(),
            "migration_sig": base64.b64encode(sig).decode()
        }

        for peer_id in list(self.app.active_sessions.keys()):
            peer = self.app.discovery.peers.get(peer_id)
            if peer:
                self.app.network.send_message(peer['ip'], peer['port'], {
                    "type": "KEY_MIGRATION_NOTIFY", 
                    "sender": self.app.user_id, 
                    "payload": payload
                })
        self.app.log("security", "Identity migration broadcasted.")

    def cmd_accept(self, *args):
        pending = getattr(self.app, "pending_transfer", None)
        if not pending:
            return self.app.log("error", "No pending transfers.")
        
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
                self.app.log("transfer", f"Accepted push. Requesting data...")
        else:
            self.app.logic.execute_approved_transfer(sender, filename)
            
        self.app.pending_transfer = None

    def cmd_deny(self, *args):
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
        self.app.log("system", "Transfer denied.")

    def run_loop(self):
        self.print_banner()
        while True:
            try:
                if getattr(self.app, "awaiting_consent", False):
                    import time
                    time.sleep(0.1)
                    continue

                user_input = input(f"\n{self.app.user_id} > ").strip().split()
                if not user_input: continue
                
                cmd, args = user_input[0].lower(), user_input[1:]
                if cmd in self.commands:
                    self.commands[cmd]["func"](*args)
                    if cmd == "exit": break
                else:
                    self.app.log("error", "Unknown command.")
            except (EOFError, KeyboardInterrupt):
                self.app.shutdown()
                break