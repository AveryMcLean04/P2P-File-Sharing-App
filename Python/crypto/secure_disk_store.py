import os
from pathlib import Path
from crypto.encryption import FileEncryptor

class SecureDiskStore:
    def __init__(self, vault_dir: str, shared_dir: str, encryptor: FileEncryptor, app=None):
        self.app = app
        self.vault_dir = Path(vault_dir)
        self.shared_dir = Path(shared_dir)
        self.encryptor = encryptor
        
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        self.shared_dir.mkdir(parents=True, exist_ok=True)

    def _log(self, category, message, end="\n"):
        if self.app:
            self.app.log(category, message, end=end)
        else:
            print(f"[{category.upper()}] {message}", end=end)

    # --- VAULT LOGIC ---

    def list_encrypted_files(self):
        """List filenames currently protected in the vault."""
        return [f.name.replace(".enc", "") for f in self.vault_dir.glob("*.enc")]

    def save_to_vault(self, filename: str, content: bytes) -> bool:
        """Encrypts data using Master Key and saves to vault."""
        try:
            clean_name = filename.replace(".enc", "")
            file_path = self.vault_dir / f"{clean_name}.enc"
            
            encrypted_data = self.encryptor.encrypt(content)
            file_path.write_bytes(encrypted_data)
            
            self._log("security", f"File '{clean_name}' secured in vault.")
            return True
        except Exception as e:
            self._log("error", f"Vault write failed: {e}")
            return False

    def load_from_vault(self, filename: str) -> bytes:
        """Decrypts and retrieves a file from the vault."""
        clean_name = filename.replace(".enc", "")
        file_path = self.vault_dir / f"{clean_name}.enc"
        
        if not file_path.exists(): return b""
            
        try:
            encrypted_blob = file_path.read_bytes()
            decrypted_data = self.encryptor.decrypt(encrypted_blob)
            
            if decrypted_data is None:
                self._log("security", f"VAULT INTEGRITY FAILURE: '{clean_name}' corrupted!")
                return b""
            return decrypted_data
        except Exception as e:
            self._log("error", f"Vault decryption failed: {e}")
            return b""

    # --- INGESTION & SHARING ---

    def ingest_file(self, source_path: str) -> bool:
        """Encrypts into Vault and places copy in Shared folder."""
        source = Path(source_path)
        if not source.exists():
            self._log("error", f"Ingest failed: {source_path} not found.")
            return False

        try:
            content = source.read_bytes()
            filename = source.name
            
            if self.save_to_vault(filename, content):
                shared_path = self.shared_dir / filename
                shared_path.write_bytes(content)
                self._log("system", f"Successfully ingested '{filename}'. Secured and Shared.")
                return True
        except Exception as e:
            self._log("error", f"Ingestion process failed: {e}")
        return False

    def uningest_file(self, filename: str) -> bool:
        """Removes from Shared folder and deletes from Vault."""
        try:
            shared_path = self.shared_dir / filename
            if shared_path.exists(): shared_path.unlink()
            
            clean_name = filename.replace(".enc", "")
            vault_path = self.vault_dir / f"{clean_name}.enc"
            if vault_path.exists(): vault_path.unlink()
                
            self._log("system", f"Successfully uningested '{filename}'.")
            return True
        except Exception as e:
            self._log("error", f"Uningestion failed: {e}")
            return False

    def list_shared_files(self):
        return [f.name for f in self.shared_dir.iterdir() 
                if f.is_file() and not f.name.startswith(".")]

    def get_shared_file_content(self, filename: str) -> bytes:
        file_path = self.shared_dir / filename
        return file_path.read_bytes() if file_path.exists() else b""

    def export_from_vault_to_shared(self, filename: str):
        data = self.load_from_vault(filename)
        if data:
            (self.shared_dir / filename).write_bytes(data)
            self._log("system", f"'{filename}' ready for sharing.")