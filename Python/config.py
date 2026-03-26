import os
from pathlib import Path
from dataclasses import dataclass

@dataclass
class AppConfig:
    user_id: str = "Alice"
    port: int = 5000
    password: str="test"
    service_type: str = "_cisc468secshare._tcp.local."
    shared_dir_name: str = "shared_test_files"
    
    @property
    def data_dir_name(self) -> str:
        """Returns the unique data directory name for this user."""
        return f"data_{self.user_id}"

    def initialize_directories(self, base_path: Path):
        """
        Creates all necessary folders and returns the paths for 
        the data, shared, and vault directories.
        """
        data_path = base_path / self.data_dir_name
        shared_path = base_path / self.shared_dir_name
        vault_path = data_path / "vault"
        
        (data_path / "keys").mkdir(parents=True, exist_ok=True)
        (data_path / "received").mkdir(parents=True, exist_ok=True)
        vault_path.mkdir(parents=True, exist_ok=True)
        shared_path.mkdir(parents=True, exist_ok=True)
        
        return data_path, shared_path, vault_path