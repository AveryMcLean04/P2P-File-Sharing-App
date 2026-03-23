import os
import sys
import time
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
    print(f"[-] Critical Error: Missing internal modules. {e}")
    sys.exit(1)

class SecureP2PApp:
    def __init__(self, user_id="Alice_Python", port=5000):
        # 1. Configuration & Storage Initialization
        self.user_id = user_id
        self.config = AppConfig(user_id=user_id, port=port)
        self.base_path = Path(__file__).resolve().parent
        self.data_path, self.vault_path = self.config.initialize_directories(self.base_path)
        
        # 2. Security & Vault Setup (Requirement 9)
        # AuthManager handles password-based key derivation (PBKDF2)
        self.auth_manager = AuthManager(key_dir=str(self.data_path / "keys"))
        
        # Unlock the vault (In a real app, prompt for password here)
        password = "test_password_123" 
        self.auth_manager.unlock_vault(password)
        
        # SecureDiskStore handles encrypted file I/O (AES-GCM)
        self.disk_store = SecureDiskStore(
            vault_dir=str(self.vault_path), 
            encryptor=self.auth_manager.local_encryptor
        )

        # 3. State Management
        self.active_sessions = {} # Stores {peer_id: {"encryptor": FileEncryptor, "ip": str}}
        self.global_registry = {} # Stores known file hashes for Redundancy (Req 5)

        # 4. Networking & Protocol Logic
        # PeerLogic bridges the Dispatcher and the Crypto/Disk modules
        self.logic = PeerLogic(self)
        self.dispatcher = MessageDispatcher(self, self.logic)
        
        self.network = NetworkManager(port, self.dispatcher.handle)
        self.discovery = MDNSHandler(user_id=self.user_id, port=port)
        
        # 5. UI
        self.cli = AppCLI(self)

    def log(self, category, message):
        """Standardized logging for the UI (Requirement 10)."""
        print(f"\n[{category.upper()}] {message}")

    def get_timestamp(self):
        """
        Requirement 10: Standardized timestamp for protocol messages.
        Returns Unix time as an integer.
        """
        return int(time.time())

    def run(self):
        self.log("system", f"Starting Secure P2P as {self.user_id}...")
        self.discovery.register_service()
        self.discovery.start_discovery()
        self.network.start_server()
        self.cli.run_loop()

    def shutdown(self):
        self.log("system", "Shutting down safely...")
        self.discovery.stop()
        self.network.stop()
        sys.exit(0)

if __name__ == "__main__":
    u_id = sys.argv[1] if len(sys.argv) > 1 else "Alice_Python"
    u_port = int(sys.argv[2]) if len(sys.argv) > 2 else 5000
    
    app = SecureP2PApp(user_id=u_id, port=u_port)
    app.run()