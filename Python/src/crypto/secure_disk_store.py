import os
from pathlib import Path
from typing import List, Dict, Optional
from .encryption import FileEncryptor

class SecureDiskStore:
    """
    Manages encrypted vault storage and plaintext shared storage.
    Updated to support file integrity hashing for peer-to-peer verification.
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
        """Returns filenames currently secured in the vault."""
        return [f.name.replace(".enc", "") for f in self.vault_dir.glob("*.enc")]

    def save_to_vault(self, filename: str, content: bytes) -> bool:
        """Encrypts and saves content into the vault with a .enc suffix."""
        try:
            clean_name = Path(filename).stem if filename.endswith(".enc") else filename
            file_path = self.vault_dir / f"{clean_name}.enc"
            file_path.write_bytes(self.encryptor.encrypt(content))
            return True
        except Exception as e:
            self.app.log("error", f"Vault write failed: {e}")
            return False

    def load_from_vault(self, filename: str) -> bytes:
        """Decrypts and returns plaintext bytes from a vault file."""
        clean_name = filename[:-4] if filename.endswith(".enc") else filename
        file_path = self.vault_dir / f"{clean_name}.enc"
        if not file_path.exists(): return b""
        
        try:
            return self.encryptor.decrypt(file_path.read_bytes()) or b""
        except Exception as e:
            self.app.log("error", f"Vault decryption failed: {e}")
            return b""

    # --- Ingestion & Sharing ---

    def ingest_file(self, source_path: str) -> bool:
        """Secures a file in the vault and places a copy in the shared directory."""
        source = Path(source_path)
        if not source.exists():
            source = Path(__file__).resolve().parent.parent.parent / source_path

        if not source.exists() or source.is_dir():
            self.app.log("error", f"Ingest failed: Invalid source '{source_path}'")
            return False

        try:
            content = source.read_bytes()
            filename = source.name
            
            # Save encrypted to Vault and plaintext to Shared
            if self.save_to_vault(filename, content):
                (self.shared_dir / filename).write_bytes(content)
                self.app.log("security", f"File '{filename}' ingested and ready for sharing.")
                return True
            return False
        except Exception as e:
            self.app.log("error", f"Ingestion failed: {e}")
            return False

    def uningest_file(self, filename: str) -> bool:
        """Removes a file from both shared and vault storage."""
        try:
            (self.shared_dir / filename).unlink(missing_ok=True)
            clean_name = filename.replace(".enc", "")
            (self.vault_dir / f"{clean_name}.enc").unlink(missing_ok=True)
            
            self.app.log("security", f"Uningested '{filename}'.")
            return True
        except Exception as e:
            self.app.log("error", f"Uningestion failed: {e}")
            return False

    def list_shared_files(self) -> List[Dict[str, str]]:
        """
        Lists shared files with their SHA-256 hashes.
        Peer B uses these hashes to verify files received from other peers.
        """
        shared_list = []
        for file_path in self.shared_dir.iterdir():
            if file_path.is_file():
                content = file_path.read_bytes()
                shared_list.append({
                    "filename": file_path.name,
                    "hash": self.encryptor.get_hash(content)
                })
        return shared_list

    def get_shared_file_content(self, filename: str) -> bytes:
        """Returns the plaintext content from the shared directory."""
        file_path = self.shared_dir / filename
        return file_path.read_bytes() if file_path.exists() else b""

    def export_from_vault_to_shared(self, filename: str):
        """Decrypts a vault file into the shared directory."""
        data = self.load_from_vault(filename)
        if data:
            (self.shared_dir / filename).write_bytes(data)
            self.app.log("security", f"'{filename}' exported to shared.")

    def decrypt_to_system(self, filename: str, destination_path: str) -> bool:
        """
        Decrypts a file from the vault and saves the plaintext to a specified path.
        """
        try:
            plaintext_content = self.load_from_vault(filename)
            
            if not plaintext_content:
                self.app.log("error", f"Decryption failed: '{filename}' not found or empty.")
                return False

            output_path = Path(destination_path)
            
            if output_path.is_dir():
                clean_name = filename.replace(".enc", "")
                output_path = output_path / clean_name

            output_path.write_bytes(plaintext_content)
            
            self.app.log("security", f"Successfully decrypted '{filename}' to {output_path}")
            return True

        except Exception as e:
            self.app.log("error", f"Manual decryption failed: {e}")
            return False