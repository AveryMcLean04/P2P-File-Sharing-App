import os
import sys
import time
import getpass
from pathlib import Path

sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

try:
    from config import AppConfig
    from discovery.mdns_handler import MDNSHandler
    from authentication.auth_manager import AuthManager
    from crypto.secure_disk_store import SecureDiskStore
    from network.dispatcher import MessageDispatcher
    from network.connection import NetworkManager
    from logic.peer_logic import PeerLogic
    from ui.cli import AppCLI
except ImportError as e:
    print(f"[FATAL] Missing internal modules. {e}")
    sys.exit(1)

class SecureP2PApp:
    def __init__(self, user_id="Alice", port=5000):
        self.user_id = user_id
        self.config = AppConfig(user_id=user_id, port=port)
        self.base_path = Path(__file__).resolve().parent
        self.data_path, self.shared_path, self.vault_path = self.config.initialize_directories(self.base_path)
        
        self.auth_manager = AuthManager(app=self, key_dir=str(self.data_path / "keys"))
        self.disk_store = None 
        
        self.active_sessions = {}
        self.logic = PeerLogic(self)
        self.dispatcher = MessageDispatcher(self, self.logic)
        self.network = NetworkManager(self, port, self.dispatcher.handle)
        self.discovery = MDNSHandler(self, user_id=self.user_id, port=port)
        self.cli = AppCLI(self)

    def login(self, max_retries=3):
        self.log("security", f"Vault access required for {self.user_id}")
        
        for attempt in range(1, max_retries + 1):
            user_input = getpass.getpass(f"[{attempt}/{max_retries}] Enter Vault Password: ")
            
            if user_input == self.config.password:
                if self.auth_manager.unlock_vault(self.config.password):
                    self.post_login_init()
                    return True
            else:
                self.log("error", "Incorrect password.")
        return False

    def post_login_init(self):
        """Initializes components requiring an unlocked vault."""
        if self.disk_store:
            return

        try:
            self.disk_store = SecureDiskStore(
                vault_dir=self.vault_path,
                shared_dir=self.shared_path,
                encryptor=self.auth_manager.local_encryptor,
                app=self
            )

            id_pub = self.auth_manager.get_public_key()
            if not id_pub or id_pub in [b"ERROR_KEY", b"ERROR_NO_KEY"]:
                raise Exception("Identity Check Failed: Private key missing or corrupted.")

            self.log("security", f"Identity Verified: [ID: {id_pub.hex()[:12]}...]")
            
            self.discovery.register_service()
            self.discovery.start_discovery()
            self.log("network", f"Discovery service active as '{self.user_id}'.")

        except Exception as e:
            self.log("error", f"Initialization failure: {str(e)}")
            raise

    def run(self):
        """Starts the active network and UI loops."""
        self.log("system", f"Starting Secure P2P as {self.user_id}...")
        self.network.start_server()
        self.cli.run_loop()

    def shutdown(self):
        """Close the active network and UI loops."""
        self.log("system", "Shutting down safely...")
        self.discovery.stop()
        self.network.broadcast_peer_left(self.user_id, self.discovery.peers)
        self.network.stop()
        sys.exit(0)

    def log(self, category, message, end="\n"):
        """Log important info."""
        print(f"[{category.upper()}] {message}", end=end, flush=True)

# --- MAIN EXECUTION BLOCK ---
if __name__ == "__main__":
    u_id = sys.argv[1] if len(sys.argv) > 1 else "Alice"
    u_port = int(sys.argv[2]) if len(sys.argv) > 2 else 5000
    
    app = SecureP2PApp(user_id=u_id, port=u_port)
    
    if app.login(max_retries=3):
        try:
            app.run()
        except KeyboardInterrupt:
            app.shutdown()
        except Exception as e:
            app.log("error", f"Application crashed: {e}")
            app.shutdown()
    else:
        app.log("fatal", "Maximum retry attempts reached. Exiting for security.")
        sys.exit(1)