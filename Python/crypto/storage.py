import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class SecureStorage:
    def __init__(self, password: str):
        """
        Initializes storage by deriving a master key from a password.
        Matches Requirement 9.
        """
        self.password = password.encode()
        # In a production app, the salt should be stored and reused.
        # For this project, we'll use a fixed salt for simplicity, 
        # but a unique one per file is better.
        self.salt = b'cisc468_fixed_salt' 

    def _derive_key(self):
        """Derives a 32-byte AES key from the user password."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        return kdf.derive(self.password)

    def save_file(self, filename, data_bytes, target_dir):
        """Encrypts and saves a file to local disk (Requirement 9)."""
        key = self._derive_key()
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        
        ciphertext = aesgcm.encrypt(nonce, data_bytes, None)
        
        file_path = os.path.join(target_dir, filename + ".enc")
        with open(file_path, "wb") as f:
            f.write(nonce + ciphertext)
        
        print(f"[*] Securely saved: {file_path}")

    def load_file(self, file_path):
        """Reads and decrypts a locally stored file."""
        key = self._derive_key()
        aesgcm = AESGCM(key)
        
        with open(file_path, "rb") as f:
            raw_data = f.read()
            
        nonce = raw_data[:12]
        ciphertext = raw_data[12:]
        
        try:
            return aesgcm.decrypt(nonce, ciphertext, None)
        except Exception:
            print("[!] Failed to decrypt local file. Wrong password?")
            return None