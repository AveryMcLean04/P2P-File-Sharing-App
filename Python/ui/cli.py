import base64
import os
from pathlib import Path

class AppCLI:
    def __init__(self, app):
        """
        The 'Face' of the application. 
        Uses app.log for all status updates to maintain UI consistency.
        """
        self.app = app
        
        self.commands = {
            "help":    {"func": self.show_help,      "desc": "Show all available commands"},
            "list":    {"func": self.cmd_list,       "desc": "List discovered network peers (mDNS)"},
            "vault":   {"func": self.cmd_vault,      "desc": "List locally secured files (Req 9)"},
            "connect": {"func": self.cmd_connect,    "desc": "Establish secure session (PFS Handshake - Req 8)"},
            "chat":    {"func": self.cmd_chat,       "desc": "Send an encrypted message (Req 7)"},
            "fetch":   {"func": self.cmd_fetch,      "desc": "Request a list of shared files (Req 4)"},
            "send":    {"func": self.cmd_send,       "desc": "Propose a file transfer (Req 3)"},
            "find":    {"func": self.cmd_find,       "desc": "Search for redundant copies of a file (Req 5)"},
            "migrate": {"func": self.cmd_migrate,    "desc": "Migrate identity keys (Req 6)"},
            "exit":    {"func": self.app.shutdown,   "desc": "Safely shut down the application"}
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

    # --- COMMANDS ---

    def cmd_list(self, *args):
        peers = self.app.discovery.peers
        if not peers:
            return self.app.log("system", "No active peers found on local network.")
        
        print(f"\n--- Discovered Peers ({len(peers)}) ---")
        for name, info in peers.items():
            status = "SECURE-SESSION" if name in self.app.active_sessions else "No-Session"
            print(f" > {name:<15} [{info['ip']}:{info['port']}] Status: {status}")

    def cmd_vault(self, *args):
        files = self.app.disk_store.list_encrypted_files()
        if not files:
            self.app.log("system", "No files in secure storage.")
        else:
            print(f"\n--- Encrypted Vault Contents ---")
            for f in files:
                # Using system log for consistent prefixing
                self.app.log("security", f"LOCKED: {f}")

    def cmd_connect(self, *args):
        target = args[0] if args else input("Connect to (UserID): ").strip()
        peer = self.app.discovery.peers.get(target)
        
        if peer:
            msg = self.app.logic.initiate_handshake(target)
            if self.app.network.send_message(peer['ip'], peer['port'], msg):
                self.app.log("security", f"Handshake dispatched to {target}...")
        else:
            self.app.log("error", f"Peer '{target}' not found via mDNS.")

    def cmd_chat(self, *args):
        target = args[0] if args else input("Recipient: ").strip()
        if not target: return

        session = self.app.active_sessions.get(target)
        if not session:
            return self.app.log("error", f"No secure tunnel to {target}.")

        text = input(f"Message for {target}: ").strip()
        if not text: return

        try:
            encryptor = session["encryptor"]
            encrypted_blob = encryptor.encrypt(text.encode())
            
            peer = self.app.discovery.peers.get(target)
            success = self.app.network.send_message(peer['ip'], peer['port'], {
                "type": "CHAT_MESSAGE",
                "sender": self.app.user_id,
                "payload": base64.b64encode(encrypted_blob).decode()
            })
            if success:
                self.app.log("system", f"Message sent to {target}.")
        except Exception as e:
            self.app.log("error", f"Failed to send: {e}")

    def cmd_fetch(self, *args):
        target = args[0] if args else input("Fetch from (UserID): ").strip()
        
        self.app.logic.request_file_list(target)

    def cmd_send(self, *args):
        target = input("Recipient: ").strip()
        filename = input("Vault Filename: ").strip()
        
        if filename not in self.app.disk_store.list_encrypted_files():
            return self.app.log("error", f"'{filename}' not in vault.")

        if target not in self.app.active_sessions:
            return self.app.log("error", "Establish a secure session first.")

        peer = self.app.discovery.peers.get(target)
        self.app.network.send_message(peer['ip'], peer['port'], {
            "type": "TRANSFER_REQUEST",
            "sender": self.app.user_id,
            "payload": {"filename": filename}
        })
        self.app.log("system", f"Request sent. Awaiting consent from {target}...")

    def cmd_find(self, *args):
        filename = args[0] if args else input("Search for file (or hash): ").strip()
        if not filename: return

        active_targets = list(self.app.active_sessions.keys())
        if not active_targets:
            return self.app.log("error", "No secure sessions active. Cannot search.")

        self.app.log("system", f"Querying {len(active_targets)} peers for '{filename}'...")
        
        for target in active_targets:
            peer = self.app.discovery.peers.get(target)
            if peer:
                self.app.network.send_message(peer['ip'], peer['port'], {
                    "type": "REDUNDANCY_QUERY",
                    "sender": self.app.user_id,
                    "payload": {
                        "filename": filename,
                        "query_id": os.urandom(4).hex()
                    }
                })

    def cmd_migrate(self):
        """Alice triggers this to tell everyone she has a new identity."""
        old_pub, new_pub, sig = self.app.auth_manager.migrate_identity()
        
        payload = {
            "old_identity": base64.b64encode(old_pub).decode(),
            "new_identity": base64.b64encode(new_pub).decode(),
            "migration_sig": base64.b64encode(sig).decode()
        }

        # Notify all active sessions
        for peer_id in list(self.app.active_sessions.keys()):
            peer = self.app.discovery.peers.get(peer_id)
            if peer:
                self.app.network.send_message(peer['ip'], peer['port'], {
                    "type": "KEY_MIGRATION_NOTIFY", 
                    "sender": self.app.user_id, 
                    "payload": payload
                })
        
        self.app.log("security", "Migration broadcast sent to all active peers.")

    def run_loop(self):
        self.print_banner()
        while True:
            try:
                # The prompt itself stays plain, but logic results use app.log
                prompt_str = f"\n{self.app.user_id} > "
                user_input = input(prompt_str).strip().split()
                
                if not user_input: continue
                
                cmd, args = user_input[0].lower(), user_input[1:]
                
                if cmd in self.commands:
                    self.commands[cmd]["func"](*args)
                    if cmd == "exit": break
                else:
                    self.app.log("error", "Unknown command. Type 'help'.")
            except (EOFError, KeyboardInterrupt):
                self.app.shutdown();