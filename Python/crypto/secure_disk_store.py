import os
from pathlib import Path
from typing import List
from crypto.encryption import FileEncryptor

class SecureDiskStore:
    """
    Manages the local filesystem for the application. 
    Handles two primary zones:
    1. Vault: Encrypted storage for private files.
    2. Shared: Plaintext storage for files currently being served to peers.
    """
    
    def __init__(self, vault_dir: str, shared_dir: str, encryptor: FileEncryptor, app):
        self.app = app
        self.vault_dir = Path(vault_dir)
        self.shared_dir = Path(shared_dir)
        self.encryptor = encryptor
        
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        self.shared_dir.mkdir(parents=True, exist_ok=True)

    # --- Vault Logic ---

    def list_encrypted_files(self) -> List[str]:
        """Returns a list of filenames currently secured within the vault."""
        return [f.name.replace(".enc", "") for f in self.vault_dir.glob("*.enc")]

    def save_to_vault(self, filename: str, content: bytes) -> bool:
        """
        Encrypts and saves raw content into the vault. 
        Automatically appends the .enc suffix if not present.
        """
        try:
            p = Path(filename)
            clean_name = p.stem if p.suffix == ".enc" else p.name
            file_path = self.vault_dir / f"{clean_name}.enc"
            
            encrypted_data = self.encryptor.encrypt(content)
            file_path.write_bytes(encrypted_data)
            
            return True
        except Exception as e:
            self.app.log("error", f"Vault write failed: {e}")
            return False

    def load_from_vault(self, filename: str) -> bytes:
        """
        Retrieves an encrypted file from the vault, decrypts it, 
        and returns the original plaintext bytes.
        """
        clean_name = filename[:-4] if filename.endswith(".enc") else filename
        file_path = self.vault_dir / f"{clean_name}.enc"
        
        if not file_path.exists(): 
            self.app.log("error", f"File {file_path} not found in vault.")
            return b""
            
        try:
            encrypted_blob = file_path.read_bytes()
            decrypted_data = self.encryptor.decrypt(encrypted_blob)
            return decrypted_data if decrypted_data else b""
        except Exception as e:
            self.app.log("error", f"Vault decryption failed: {e}")
            return b""

    # --- Ingestion & Sharing ---

    def ingest_file(self, source_path: str) -> bool:
        """
        Secures a local file by:
        1. Encrypting it into the Vault for long-term storage.
        2. Placing a plaintext copy in the Shared folder for peer discovery.
        """
        source = Path(source_path)
        
        if not source.exists():
            project_root = Path(__file__).resolve().parent.parent.parent
            source = project_root / source_path

        if not source.exists():
            self.app.log("error", f"Ingest failed: Source file '{source_path}' not found.")
            return False

        if source.is_dir():
            self.app.log("error", f"Ingest failed: '{source.name}' is a directory.")
            return False

        try:
            content = source.read_bytes()
            filename = source.name
            
            clean_name = filename[:-4] if filename.endswith(".enc") else filename
            vault_path = self.vault_dir / f"{clean_name}.enc"
            
            encrypted_data = self.encryptor.encrypt(content)
            if not encrypted_data:
                raise ValueError("Encryption returned empty data.")
                
            vault_path.write_bytes(encrypted_data)
            
            shared_path = self.shared_dir / filename
            shared_path.write_bytes(content)
            
            if vault_path.exists() and shared_path.exists():
                self.app.log("security", f"File '{filename}' secured in vault.")
                return True
            else:
                self.app.log("error", "Ingest failed: Files were not written to disk.")
                return False
                
        except Exception as e:
            self.app.log("error", f"Ingestion process failed: {e}")
            if 'vault_path' in locals() and vault_path.exists(): vault_path.unlink()
            if 'shared_path' in locals() and shared_path.exists(): shared_path.unlink()
            return False

    def uningest_file(self, filename: str) -> bool:
        """
        Removes a file from visibility by:
        1. Deleting it from the Shared folder.
        2. Deleting it from the Vault.
        3. Broadcasting a removal notification to all active peers.
        """
        try:
            shared_path = self.shared_dir / filename
            if shared_path.exists(): 
                shared_path.unlink()
            
            clean_name = filename.replace(".enc", "")
            vault_path = self.vault_dir / f"{clean_name}.enc"
            if vault_path.exists(): 
                vault_path.unlink()
                
            self.app.log("security", f"Successfully uningested '{filename}'.")

            if self.app and hasattr(self.app, 'active_sessions'):
                for peer_id in list(self.app.active_sessions.keys()):
                    peer = self.app.discovery.peers.get(peer_id)
                    if peer:
                        self.app.network.send_message(peer['ip'], peer['port'], {
                            "type": "FILE_REMOVAL_NOTIFY",
                            "sender": self.app.user_id,
                            "payload": {"filename": filename}
                        })
            return True
        except Exception as e:
            self.app.log("error", f"Uningestion failed: {e}")
            return False

    def list_shared_files(self) -> List[str]:
        """Lists filenames currently residing in the vault (available for sharing)."""
        return [f.name.replace(".enc", "") for f in self.vault_dir.iterdir() if f.is_file()]

    def get_shared_file_content(self, filename: str) -> bytes:
        """Reads and returns the plaintext content from the shared directory."""
        file_path = self.shared_dir / filename
        return file_path.read_bytes() if file_path.exists() else b""

    def export_from_vault_to_shared(self, filename: str):
        """
        Decrypts a file from the vault and places a plaintext copy 
        in the shared directory to make it available to the network.
        """
        data = self.load_from_vault(filename)
        if data:
            (self.shared_dir / filename).write_bytes(data)
            self.app.log("security", f"'{filename}' ready for sharing.")