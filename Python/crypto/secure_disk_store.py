import os
from crypto.encryption import FileEncryptor

class SecureDiskStore:
    def __init__(self, vault_dir: str, encryptor: FileEncryptor):
        self.vault_dir = vault_dir
        self.encryptor = encryptor
        if not os.path.exists(self.vault_dir):
            os.makedirs(self.vault_dir)

    def save_file(self, filename: str, content: bytes):
        """Encrypts and saves a file to the vault."""
        encrypted_data = self.encryptor.encrypt(content)
        file_path = os.path.join(self.vault_dir, f"{filename}.enc")
        with open(file_path, "wb") as f:
            f.write(encrypted_data)
        return file_path

    def load_file(self, filename: str) -> bytes:
        """Reads and decrypts a file from the vault."""
        file_path = os.path.join(self.vault_dir, f"{filename}.enc")
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File {filename} not found in vault.")
            
        with open(file_path, "rb") as f:
            encrypted_blob = f.read()
            
        decrypted_data = self.encryptor.decrypt(encrypted_blob)
        if decrypted_data is None:
            raise ValueError(f"Integrity check failed for {filename}. Possible tampering.")
        return decrypted_data

    def list_encrypted_files(self):
        """Requirement 4 helper: List files available to share."""
        return [f.replace(".enc", "") for f in os.listdir(self.vault_dir) if f.endswith(".enc")]