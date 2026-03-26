import os
from pathlib import Path
from crypto.encryption import FileEncryptor

class SecureDiskStore:
    def __init__(self, vault_dir: str, encryptor: FileEncryptor, app=None):
        """
        Requirement 9: Securely manages encrypted file I/O.
        :param vault_dir: Path to the encrypted storage folder.
        :param encryptor: The FileEncryptor instance (using the Master Key).
        :param app: The main SecureP2PApp instance for centralized logging.
        """
        self.app = app
        self.vault_dir = Path(vault_dir)
        self.encryptor = encryptor
        
        # Ensure vault directory exists
        self.vault_dir.mkdir(parents=True, exist_ok=True)

    def _log(self, category: str, message: str):
        """Internal helper to use app.log if available."""
        if self.app:
            self.app.log(category, message)
        else:
            print(f"[{category.upper()}] {message}")

    def save_file(self, filename: str, content: bytes) -> str:
        """Requirement 3 & 9: Encrypts and saves a file to the vault."""
        try:
            encrypted_data = self.encryptor.encrypt(content)
            # Ensure filename doesn't have double extensions
            clean_name = filename.replace(".enc", "")
            file_path = self.vault_dir / f"{clean_name}.enc"
            
            file_path.write_bytes(encrypted_data)
            self._log("system", f"File '{clean_name}' secured in vault.")
            return str(file_path)
        except Exception as e:
            self._log("error", f"Failed to save {filename}: {e}")
            return ""

    def load_file(self, filename: str) -> bytes:
        """Requirement 9: Reads and decrypts a file from the vault."""
        clean_name = filename.replace(".enc", "")
        file_path = self.vault_dir / f"{clean_name}.enc"
        
        if not file_path.exists():
            self._log("error", f"Vault error: {clean_name} not found.")
            return b""
            
        encrypted_blob = file_path.read_bytes()
        decrypted_data = self.encryptor.decrypt(encrypted_blob)
        
        if decrypted_data is None:
            self._log("security", f"Integrity Failure: {clean_name} is corrupted or tampered!")
            return b""
            
        return decrypted_data

    def list_encrypted_files(self):
        """Requirement 4 & 9: List filenames currently protected in the vault."""
        if not self.vault_dir.exists():
            return []
        return [f.name.replace(".enc", "") for f in self.vault_dir.glob("*.enc")]