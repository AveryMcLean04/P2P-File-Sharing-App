import base64
import os
from pathlib import Path

class AppCLI:
    def __init__(self, app):
        """
        The 'Face' of the application. 
        Integrates with AuthManager, SecureDiskStore, and mDNSHandler.
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
            "rotate":  {"func": self.cmd_rotate,     "desc": "Rotate identity keys (Req 6)"},
            "exit":    {"func": self.app.shutdown,   "desc": "Safely shut down the application"}
        }

    def print_banner(self):
        banner = f" SECURE P2P: {self.app.user_id} "
        print(f"\n{'='*50}\n{banner:^50}\n{'='*50}")
        print("[*] Vault Unlocked. System Ready.")

    def show_help(self, *args):
        print(f"\n{'COMMAND':<12} | {'DESCRIPTION'}")
        print("-" * 52)
        for cmd, info in self.commands.items():
            print(f"{cmd:<12} | {info['desc']}")

    # --- COMMANDS ---

    def cmd_list(self, *args):
        """Displays peers found by mDNSHandler."""
        peers = self.app.discovery.peers
        if not peers:
            return print("[-] No active peers found on local network.")
        
        print(f"\n--- Discovered Peers ({len(peers)}) ---")
        for name, info in peers.items():
            status = "SECURE-SESSION" if name in self.app.active_sessions else "No-Session"
            print(f" > {name:<15} [{info['ip']}:{info['port']}] Status: {status}")

    def cmd_vault(self, *args):
        """Requirement 9: List files secured by SecureDiskStore."""
        files = self.app.disk_store.list_encrypted_files()
        if not files:
            print("[!] No files in secure storage.")
        else:
            print(f"\n--- Encrypted Vault Contents ---")
            for f in files:
                print(f" [LOCKED] {f}")

    def cmd_connect(self, *args):
        """Initiates Perfect Forward Secrecy Handshake (Req 8)."""
        target = args[0] if args else input("Connect to (UserID): ").strip()
        peer = self.app.discovery.peers.get(target)
        
        if peer:
            msg = self.app.logic.initiate_handshake(target)
            self.app.network.send_message(peer['ip'], peer['port'], msg)
            print(f"[*] Handshake dispatched to {target}...")
        else:
            print(f"[-] Peer '{target}' not found via mDNS.")

    def cmd_chat(self, *args):
        """Encrypts and sends a message (Req 7)."""
        target = input("Recipient: ").strip()
        if target not in self.app.active_sessions:
            return print(f"[-] Error: No secure tunnel. Run 'connect {target}' first.")
        
        text = input(f"Message for {target}: ").strip()
        if not text: return

        encryptor = self.app.active_sessions[target]["encryptor"]
        encrypted_blob = encryptor.encrypt(text.encode())
        
        peer = self.app.discovery.peers.get(target)
        self.app.network.send_message(peer['ip'], peer['port'], {
            "type": "CHAT_MESSAGE",
            "sender": self.app.user_id,
            "payload": base64.b64encode(encrypted_blob).decode()
        })
        print(f"[Self -> {target}]: {text}")

    def cmd_fetch(self, *args):
        """Requirement 4: Request a list of shared files from a peer."""
        target = args[0] if args else input("Fetch file list from (UserID): ").strip()
        
        # 1. Check if peer exists in discovery
        peer = self.app.discovery.peers.get(target)
        if not peer:
            return print(f"[-] Peer '{target}' not found via mDNS.")

        # 2. Ensure a secure session exists (Req 8)
        if target not in self.app.active_sessions:
            return print(f"[-] Error: No secure session with {target}. Run 'connect {target}' first.")

        # 3. Dispatch the request
        self.app.network.send_message(peer['ip'], peer['port'], {
            "type": "FILE_LIST_REQUEST",
            "sender": self.app.user_id,
            "payload": {} 
        })
        
        print(f"[*] Requesting file catalog from {target}...")

    def cmd_send(self, *args):
        """Proposes transfer of a file from the secure vault (Req 3)."""
        target = input("Recipient: ").strip()
        filename = input("Vault Filename: ").strip()
        
        if filename not in self.app.disk_store.list_encrypted_files():
            return print(f"[-] Error: '{filename}' not in vault.")

        if target not in self.app.active_sessions:
            return print(f"[-] Error: Establish a secure session first.")

        peer = self.app.discovery.peers.get(target)
        self.app.network.send_message(peer['ip'], peer['port'], {
            "type": "TRANSFER_REQUEST",
            "sender": self.app.user_id,
            "payload": {"filename": filename}
        })
        print(f"[*] Request sent. Awaiting consent from {target}...")

    def cmd_find(self, *args):
        """Requirement 5: Search for redundant copies of a file across the network."""
        filename = args[0] if args else input("Search for file (or hash): ").strip()
        if not filename: return

        active_targets = list(self.app.active_sessions.keys())
        
        if not active_targets:
            return print("[-] No secure sessions active. Cannot perform network search.")

        print(f"[*] Querying {len(active_targets)} peers for '{filename}'...")
        
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
        
        print("[*] Search broadcasted. Results will appear as peers respond.")

    def cmd_rotate(self, *args):
        """Requirement 6: Rotate identity keys and notify sessions."""
        confirm = input("Are you sure? This rotates your long-term identity (y/n): ")
        if confirm.lower() != 'y': return

        new_priv, new_pub = self.app.auth_manager.generate_new_identity()

        self.app.auth_manager.save_identity_securely(new_priv)
        
        payload = {"new_pubkey": base64.b64encode(new_pub).decode()}
        for name in self.app.active_sessions:
            peer = self.app.discovery.peers.get(name)
            if peer:
                self.app.network.send_message(peer['ip'], peer['port'], {
                    "type": "KEY_MIGRATION", "sender": self.app.user_id, "payload": payload
                })
        print("[+] Identity rotated and peers notified.")

    def run_loop(self):
        self.print_banner()
        while True:
            try:
                raw = input(f"\n{self.app.user_id} > ").strip().split()
                if not raw: continue
                cmd, args = raw[0].lower(), raw[1:]
                if cmd in self.commands:
                    self.commands[cmd]["func"](*args)
                    if cmd == "exit": break
                else:
                    print(f"[-] Unknown command. Type 'help'.")
            except (EOFError, KeyboardInterrupt):
                self.app.shutdown(); break