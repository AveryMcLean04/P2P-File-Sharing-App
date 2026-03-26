import os
import sys
import time
import getpass  # For secure password input
from pathlib import Path

# Path setup for internal modules
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
    def __init__(self, user_id="Alice_Python", port=5000):
        # 1. Configuration & Storage Initialization
        self.user_id = user_id
        self.config = AppConfig(user_id=user_id, port=port)
        self.base_path = Path(__file__).resolve().parent
        self.data_path, self.vault_path = self.config.initialize_directories(self.base_path)
        
        # 2. Security & Vault Setup (Requirement 9)
        self.auth_manager = AuthManager(key_dir=str(self.data_path / "keys"))
        
        # We delay initializing the disk_store until the vault is unlocked
        self.disk_store = SecureDiskStore(vault_dir=str(self.vault_path), encryptor=self.auth_manager.local_encryptor, app=self)

        # 3. State Management
        self.active_sessions = {}
        self.global_registry = {}

        # 4. Networking & Protocol Logic (Bridging occurs after unlock)
        self.logic = PeerLogic(self)
        self.dispatcher = MessageDispatcher(self, self.logic)
        self.network = NetworkManager(self, port, self.dispatcher.handle)
        self.discovery = MDNSHandler(self, user_id=self.user_id, port=port)   
        
        # 5. UI
        self.cli = AppCLI(self)

    def login(self, max_retries=3):
        """
        Force the user to type the hardcoded password from AppConfig.
        """
        self.log("security", f"Vault access required for {self.user_id}")
        
        for attempt in range(1, max_retries + 1):

            prompt = f"[{attempt}/{max_retries}] Enter Vault Password: "
            self.log("security", prompt, end="")
            
            user_input = getpass.getpass("")
            
            if user_input == self.config.password:
                if self.auth_manager.unlock_vault(self.config.password):
                    self.disk_store = SecureDiskStore(
                        vault_dir=str(self.vault_path), 
                        encryptor=self.auth_manager.local_encryptor
                    )
                    self.log("system", "Vault unlocked.")
                    return True
            else:

                print() 
                self.log("error", "Incorrect password.")
        
        return False

    def log(self, category, message, end="\n"):
        """Standardized logging for the UI."""
        print(f"[{category.upper()}] {message}", end=end)

    def run(self):
        self.log("system", f"Starting Secure P2P as {self.user_id}...")
        self.discovery.register_service()
        self.discovery.start_discovery()
        self.network.start_server()
        self.cli.run_loop()

    def shutdown(self):
        self.log("system", "Shutting down safely...")
        self.discovery.stop()
        self.network.broadcast_peer_left(self.user_id, self.discovery.peers)
        self.network.stop()
        sys.exit(0)

# --- MAIN EXECUTION BLOCK ---

if __name__ == "__main__":

    u_id = sys.argv[1] if len(sys.argv) > 1 else "Alice_Python"
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