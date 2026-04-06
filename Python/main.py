import os
import sys
import getpass
from pathlib import Path

sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

try:
    from src.config import AppConfig
    from src.authentication.auth_manager import AuthManager
    from src.crypto.secure_disk_store import SecureDiskStore
    from src.network.mdns_handler import MDNSHandler
    from src.network.dispatcher import MessageDispatcher
    from src.network.connection import NetworkManager
    from src.logic.peer_logic import PeerLogic
    from src.ui.cli import AppCLI
except ImportError as e:
    print(f"[FATAL] Dependency error: {e}")
    sys.exit(1)

class SecureP2PApp:
    """
    The central coordinator for the Secure P2P system.
    Orchestrates identity, networking, storage, and the user interface.
    """
    
    def __init__(self, user_id: str = "Alice", port: int = 5000):
        self.user_id = user_id
        self.config = AppConfig(user_id=user_id, port=port)
        self.base_path = Path(__file__).resolve().parent
        
        # Setup filesystem hierarchy (Data, Shared, Vault)
        self.data_path, self.shared_path, self.vault_path = self.config.initialize_directories(self.base_path)
        
        # Core Managers
        self.auth_manager = AuthManager(app=self, key_dir=str(self.data_path / "keys"))
        self.disk_store = None  # Deferred until Vault is unlocked
        
        # Session and Logic State
        self.active_sessions = {}
        self.logic = PeerLogic(self)
        self.dispatcher = MessageDispatcher(self, self.logic)
        
        # Networking Components
        self.network = NetworkManager(self, port, self.dispatcher.handle)
        self.discovery = MDNSHandler(self, user_id=self.user_id, port=port)
        
        # User Interface
        self.cli = AppCLI(self)

    def login(self, max_retries: int = 3) -> bool:
        """
        Secures the application start. Users must provide the correct 
        Vault password to derive the local encryption keys.
        """
        self.log("security", f"Vault access requested for user: {self.user_id}")
        
        for attempt in range(1, max_retries + 1):
            password = getpass.getpass(f"[{attempt}/{max_retries}] Enter Vault Password: ")
            
            if password == self.config.password:
                if self.auth_manager.unlock_vault(password):
                    self.post_login_init()
                    return True
            
            self.log("error", "Invalid credentials.")
            
        return False

    def post_login_init(self):
        """
        Starts services that depend on the unlocked Vault (Encryption and Discovery).
        """
        if self.disk_store: return # Prevent double-initialization

        try:
            self.disk_store = SecureDiskStore(
                vault_dir=self.vault_path,
                shared_dir=self.shared_path,
                encryptor=self.auth_manager.local_encryptor,
                app=self
            )

            id_pub = self.auth_manager.get_public_key()
            if not id_pub:
                raise ValueError("Identity key is missing or corrupted.")

            self.log("security", f"Identity Verified: [ID: {id_pub.hex()[:12]}...]")
            
            self.discovery.register_service()
            self.discovery.start_discovery()
            self.log("network", f"mDNS Discovery active as '{self.user_id}'.")

        except Exception as e:
            self.log("error", f"Boot failure: {e}")
            self.shutdown()

    def run(self):
        """Starts the TCP server and enters the interactive CLI loop."""
        self.log("system", f"Secure P2P Node starting on port {self.config.port}...")
        self.network.start_server()
        self.cli.run_loop()

    def shutdown(self):
        """
        Gracefully closes all threads and notifies peers of departure 
        to maintain network hygiene.
        """
        self.log("system", "Performing graceful shutdown...")
        try:
            self.network.broadcast_peer_left(self.user_id, self.discovery.peers)
            self.discovery.stop()
            self.network.stop()
        except Exception as e:
            self.log("error", f"Shutdown warning: {e}")
        
        self.log("system", "Goodbye.")
        os._exit(0)

    def log(self, category: str, message: str):
        """Centralized logging for the UI."""
        print(f"[{category.upper()}] {message}", flush=True)

# --- Entry Point ---
if __name__ == "__main__":
    u_id = sys.argv[1] if len(sys.argv) > 1 else "Alice"
    u_port = int(sys.argv[2]) if len(sys.argv) > 2 else 5000
    
    app = SecureP2PApp(user_id=u_id, port=u_port)
    
    try:
        if app.login():
            app.run()
        else:
            app.log("fatal", "Authentication failed. Exiting.")
            sys.exit(1)
    except KeyboardInterrupt:
        app.shutdown()
    except Exception as e:
        app.log("error", f"Critical crash: {e}")
        app.shutdown()