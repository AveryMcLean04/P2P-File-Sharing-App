import os
from pathlib import Path
from crypto.encryption import FileEncryptor

class SecureDiskStore:
    def __init__(self, vault_dir: str, shared_dir: str, encryptor: FileEncryptor, app=None):
        """
        Requirement 9: Securely manages encrypted file I/O.
        """
        self.app = app
        self.vault_dir = Path(vault_dir)
        self.shared_dir = Path(shared_dir)
        self.encryptor = encryptor
        
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        self.shared_dir.mkdir(parents=True, exist_ok=True)

    def _log(self, category, message):
        if self.app:
            self.app.log(category, message)
        else:
            print(f"[{category.upper()}] {message}")

    # --- INGESTION LOGIC ---

    def import_external_file(self, source_path: str):
        """
        Requirement 9: Takes a plaintext file from outside the system,
        encrypts it, and secures it in the Vault.
        """
        source = Path(source_path)
        if not source.exists():
            self._log("error", f"Import failed: {source_path} not found.")
            return False

        try:
            content = source.read_bytes()
            # Save it to vault (this handles the encryption)
            success = self.save_to_vault(source.name, content)
            
            if success:
                self._log("system", f"Successfully imported '{source.name}' to Vault.")
                return True
        except Exception as e:
            self._log("error", f"Failed to import file: {e}")
        return False

    # --- SHARED FOLDER LOGIC (Requirement 4) ---

    def list_shared_files(self):
        """Requirement 4: Returns names of files peers can request."""
        if not self.shared_dir.exists():
            return []
        return [f.name for f in self.shared_dir.iterdir() 
                if f.is_file() and not f.name.startswith(".")]

    def get_shared_file_content(self, filename: str) -> bytes:
        """Requirement 3: Reads content from the shared folder for P2P transfer."""
        file_path = self.shared_dir / filename
        if file_path.exists():
            return file_path.read_bytes()
        
        self._log("error", f"Shared file '{filename}' not found.")
        return b""

    # --- VAULT LOGIC (Requirement 9) ---

    def list_encrypted_files(self):
        """Requirement 9: List filenames currently protected in the vault."""
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
            self._log("error", f"Vault write failed: {str(e)}")
            return False

    def load_from_vault(self, filename: str) -> bytes:
        """Decrypts and retrieves a file from the vault."""
        clean_name = filename.replace(".enc", "")
        file_path = self.vault_dir / f"{clean_name}.enc"
        
        if not file_path.exists():
            return b""
            
        try:
            encrypted_blob = file_path.read_bytes()
            decrypted_data = self.encryptor.decrypt(encrypted_blob)
            
            if decrypted_data is None:
                self._log("security", f"VAULT INTEGRITY FAILURE: '{clean_name}' corrupted!")
                return b""
                
            return decrypted_data
        except Exception as e:
            self._log("error", f"Vault decryption failed: {str(e)}")
            return b""

    # --- NEW INGESTION LOGIC (Requirement 9 & 4) ---

    def ingest_file(self, source_path: str) -> bool:
        """
        Takes a plaintext file, encrypts it into the Vault, 
        and places a copy in the Shared folder for peers.
        """
        source = Path(source_path)
        if not source.exists():
            self._log("error", f"Ingest failed: {source_path} not found.")
            return False

        try:
            content = source.read_bytes()
            filename = source.name
            
            # 1. Save Encrypted to Vault
            if self.save_to_vault(filename, content):
                # 2. Place Plaintext in Shared Folder
                shared_path = self.shared_dir / filename
                shared_path.write_bytes(content)
                
                self._log("system", f"Successfully ingested '{filename}'. It is now secured and shared.")
                return True
        except Exception as e:
            self._log("error", f"Ingestion process failed: {e}")
        return False

    def uningest_file(self, filename: str) -> bool:
        """
        Removes the file from the Shared folder (stopping P2P access)
        and deletes the encrypted version from the Vault.
        """
        try:
            # 1. Remove from Shared
            shared_path = self.shared_dir / filename
            if shared_path.exists():
                shared_path.unlink()
            
            # 2. Remove from Vault
            clean_name = filename.replace(".enc", "")
            vault_path = self.vault_dir / f"{clean_name}.enc"
            if vault_path.exists():
                vault_path.unlink()
                
            self._log("system", f"Successfully uningested '{filename}'. Removed from Vault and Sharing.")
            return True
        except Exception as e:
            self._log("error", f"Uningestion failed: {e}")
            return False

    # --- UTILITY ---

    def export_from_vault_to_shared(self, filename: str):
        """Requirement 4: Places a decrypted copy in the shared folder."""
        data = self.load_from_vault(filename)
        if data:
            target_path = self.shared_dir / filename
            target_path.write_bytes(data)
            self._log("system", f"'{filename}' is now ready for sharing.")