import os
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

class FileEncryptor:
    """
    Provides AES-256-GCM encryption and SHA-256 hashing.
    Ensures confidentiality and cross-peer file integrity.
    """
    NONCE_SIZE = 12
    TAG_SIZE = 16

    def __init__(self, key: bytes, app):
        if len(key) != 32:
            raise ValueError("AES-256 requires a 32-byte key.")
        self.aes_gcm = AESGCM(key)
        self.app = app

    # --- Integrity & Hashing ---

    @staticmethod
    def get_hash(data: bytes) -> str:
        """Generates a SHA-256 hex string for file verification."""
        digest = hashes.Hash(hashes.SHA256())
        digest.update(data)
        return digest.finalize().hex()

    def verify_file_integrity(self, data: bytes, expected_hash: str) -> bool:
        """Compares calculated data hash against a trusted manifest hash."""
        actual_hash = self.get_hash(data)
        if actual_hash == expected_hash:
            return True
        self.app.log("error", f"Integrity Failure: Hash mismatch.")
        return False

    # --- Encryption Operations ---

    def encrypt(self, plaintext: bytes, associated_data: bytes = None) -> bytes:
        """Encrypts data and prepends a random 12-byte nonce."""
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()
        
        nonce = os.urandom(self.NONCE_SIZE)
        return nonce + self.aes_gcm.encrypt(nonce, plaintext, associated_data)

    def decrypt(self, encrypted_blob: bytes, associated_data: bytes = None) -> Optional[bytes]:
        """Decrypts data and verifies the GCM authentication tag."""
        if len(encrypted_blob) < self.NONCE_SIZE + self.TAG_SIZE:
            return None

        nonce = encrypted_blob[:self.NONCE_SIZE]
        ciphertext = encrypted_blob[self.NONCE_SIZE:]

        try:
            return self.aes_gcm.decrypt(nonce, ciphertext, associated_data)
        except InvalidTag:
            self.app.log("error", "Auth Failure: Data tampered or wrong key.")
            return None
        except Exception as e:
            self.app.log("error", f"Decryption error: {e}")
            return None

    @staticmethod
    def generate_random_key() -> bytes:
        """Generates a secure 32-byte symmetric key."""
        return os.urandom(32)