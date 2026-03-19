import os
import sys
import time
import base64
import hashlib
from pathlib import Path
from dataclasses import dataclass

# Path setup and internal imports
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))
try:
    from config import AppConfig
    from discovery.mdns_handler import MDNSHandler
    from crypto.key_manager import KeyManager
    from crypto.session import SessionManager
    from crypto.encryption import FileEncryptor
    from crypto.storage import SecureStorage
    from network.dispatcher import MessageDispatcher
    from network.connection import NetworkManager
    from ui.cli import AppCLI
    from logic.peer_logic import PeerLogic
except ImportError as e:
    print(f"[-] Critical Error: Missing internal modules. {e}")
    sys.exit(1)

class SecureP2PApp:
    def __init__(self, user_id="Alice_Python", port=5000):

        # 1. Config & Paths
        self.config = AppConfig(user_id=user_id, port=port)
        self.base_path = Path(__file__).resolve().parent
        self.data_path, self.shared_path = self.config.initialize_directories(self.base_path)
        
        # 2. State
        self.active_sessions = {}
        self.global_registry = {}

        # 3. Components
        self.logic = PeerLogic(self)
        self.dispatcher = MessageDispatcher(self, self.logic)
        self.network = NetworkManager(self.config.port, self.dispatcher.handle)
        self.key_mgr = KeyManager(keys_dir=str(self.data_path / "keys"))
        self.key_mgr.load_or_generate_keys()
        self.storage = SecureStorage(password="my_secure_password_123")
        self.discovery = MDNSHandler(self.config.user_id, self.config.port, self.config.service_type)
        self.cli = AppCLI(self)

    def log(self, category, message):
        print(f"[{time.strftime('%H:%M:%S')}] [{category.upper():^10}] {message}")

    def run(self):
        self.discovery.start_discovery()
        self.network.start_server()
        self.cli.run_loop()

    def shutdown(self):
        self.discovery.stop_discovery()
        self.network.stop()

if __name__ == "__main__":
    u_id = sys.argv[1] if len(sys.argv) > 1 else "Alice_Python"
    u_port = int(sys.argv[2]) if len(sys.argv) > 2 else 5000
    app = SecureP2PApp(user_id=u_id, port=u_port)
    app.run()