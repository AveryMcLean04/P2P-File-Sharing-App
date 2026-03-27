import os
from pathlib import Path
from crypto.encryption import FileEncryptor

class SecureDiskStore:
    def __init__(self, vault_dir: str, shared_dir: str, encryptor: FileEncryptor, app=None):
        """
        Requirement 9: Securely manages encrypted file I/O.
        :param vault_dir: Path to the encrypted private storage (The Vault).
        :param shared_dir: Path to the plaintext public storage (The Shared Folder).
        :param encryptor: The FileEncryptor instance (using the Master Key).
        :param app: The main SecureP2PApp instance for standardized logging.
        """
        self.app = app
        self.vault_dir = Path(vault_dir)
        self.shared_dir = Path(shared_dir)
        self.encryptor = encryptor
        
        # Ensure directories exist
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        self.shared_dir.mkdir(parents=True, exist_ok=True)

    def _log(self, category, message):
        """Helper to ensure we use the standardized app logger."""
        if self.app:
            self.app.log(category, message)
        else:
            print(f"[{category.upper()}] {message}")

    # --- SHARED FOLDER LOGIC (Requirement 4) ---

    def list_shared_files(self):
        """Requirement 4: Returns names of files peers can request (No consent required for list)."""
        if not self.shared_dir.exists():
            return []
        # Filter for files and ignore hidden system files
        return [f.name for f in self.shared_dir.iterdir() 
                if f.is_file() and not f.name.startswith(".")]

    def get_shared_file_content(self, filename: str) -> bytes:
        """Requirement 3: Reads content from the shared folder to be sent to a peer."""
        file_path = self.shared_dir / filename
        if file_path.exists():
            return file_path.read_bytes()
        
        self._log("error", f"Shared file '{filename}' not found.")
        return b""

    # --- VAULT LOGIC (Requirement 9) ---

    def list_encrypted_files(self):
        """Requirement 9: List filenames currently protected at rest in the vault."""
        if not self.vault_dir.exists():
            return []
        return [f.name.replace(".enc", "") for f in self.vault_dir.glob("*.enc")]

    def save_to_vault(self, filename: str, content: bytes) -> bool:
        """
        Requirement 3 & 9: Encrypts data and saves it into the secure vault.
        Ensures that an attacker stealing the device cannot read the file.
        """
        try:
            # Normalize extension to prevent 'file.enc.enc'
            clean_name = filename.replace(".enc", "")
            file_path = self.vault_dir / f"{clean_name}.enc"
            
            # Encrypt using the Master Key (AES-256-GCM)
            encrypted_data = self.encryptor.encrypt(content)
            file_path.write_bytes(encrypted_data)
            
            self._log("security", f"File '{clean_name}' encrypted and stored in vault.")
            return True
        except Exception as e:
            self._log("error", f"Vault encryption/write failed: {str(e)}")
            return False

    def load_from_vault(self, filename: str) -> bytes:
        """
        Requirement 9: Decrypts and retrieves a file from the vault.
        Validates integrity during decryption.
        """
        clean_name = filename.replace(".enc", "")
        file_path = self.vault_dir / f"{clean_name}.enc"
        
        if not file_path.exists():
            self._log("error", f"Vault file '{clean_name}' does not exist.")
            return b""
            
        try:
            encrypted_blob = file_path.read_bytes()
            decrypted_data = self.encryptor.decrypt(encrypted_blob)
            
            if decrypted_data is None:
                self._log("security", f"VAULT INTEGRITY FAILURE: '{clean_name}' is corrupted or tampered!")
                return b""
                
            return decrypted_data
        except Exception as e:
            self._log("error", f"Vault decryption failed: {str(e)}")
            return b""

    # --- UTILITY ---

    def export_from_vault_to_shared(self, filename: str):
        """
        Requirement 4: Moves a file from private vault to public shared folder.
        This decrypts the file so it is 'ready' for peers to request it.
        """
        data = self.load_from_vault(filename)
        if data:
            target_path = self.shared_dir / filename
            target_path.write_bytes(data)
            self._log("system", f"Exported '{filename}' to shared folder.")
        else:
            self._log("error", f"Failed to export '{filename}' for sharing.")