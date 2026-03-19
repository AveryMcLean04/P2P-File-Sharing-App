import os
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

class SecureStorage:
    def __init__(self, password: str):
        """
        Initializes storage by preparing to derive keys from a password.
        Requirement 9: Data-at-rest encryption.
        """
        self.password = password.encode()
        self.iterations = 100000 # Standard for PBKDF2-SHA256

    def _derive_key(self, salt: bytes) -> bytes:
        """
        Derives a unique 32-byte AES key using PBKDF2.
        Using a per-file salt prevents pre-computation attacks.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.iterations,
        )
        return kdf.derive(self.password)

    def save_file(self, filename: str, data_bytes: bytes, target_dir: str):
        """
        Encrypts and saves a file to local disk.
        Structure: [16-byte Salt] + [12-byte Nonce] + [Ciphertext + Tag]
        """
        # 1. Generate unique randomness for this specific file
        salt = os.urandom(16) 
        nonce = os.urandom(12)
        
        # 2. Derive key and encrypt
        key = self._derive_key(salt)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, data_bytes, None)
        
        # 3. Write to disk
        target_path = Path(target_dir) / f"{filename}.enc"
        target_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(target_path, "wb") as f:
            # We store the salt and nonce so we can decrypt it later
            f.write(salt + nonce + ciphertext)
        
        print(f"[*] Securely saved (encrypted): {target_path}")

    def load_file(self, file_path: str) -> bytes | None:
        """
        Reads, derives the specific key using the stored salt, and decrypts.
        """
        path = Path(file_path)
        if not path.exists():
            print(f"[!] File not found: {file_path}")
            return None

        with open(path, "rb") as f:
            raw_data = f.read()

        if len(raw_data) < 44: # 16 (salt) + 12 (nonce) + 16 (min tag size)
            print("[!] File corrupted or too small.")
            return None
            
        # 1. Extract the pieces
        salt = raw_data[:16]
        nonce = raw_data[16:28]
        ciphertext = raw_data[28:]
        
        # 2. Re-derive the exact key used for THIS file
        key = self._derive_key(salt)
        aesgcm = AESGCM(key)
        
        try:
            return aesgcm.decrypt(nonce, ciphertext, None)
        except InvalidTag:
            print("[!] Decryption failed. Wrong password or file tampered with.")
            return None
        except Exception as e:
            print(f"[!] Storage error: {e}")
            return None