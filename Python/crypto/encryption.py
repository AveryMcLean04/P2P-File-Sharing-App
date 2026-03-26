import os
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

class FileEncryptor:
    # AES-GCM standard nonce size is 12 bytes
    NONCE_SIZE = 12
    # GCM tag is 16 bytes (appended to ciphertext by cryptography library)
    TAG_SIZE = 16

    def __init__(self, key: bytes, app=None):
        """
        Initializes the AES-256-GCM encryptor.
        :param key: 32-byte key derived from password or DH exchange.
        :param app: The main SecureP2PApp instance for centralized logging.
        """
        if len(key) != 32:
            raise ValueError("AES-256 requires a 32-byte key.")
        self.aes_gcm = AESGCM(key)
        self.app = app

    def _log(self, category: str, message: str):
        """Internal helper to use app.log if available."""
        if self.app:
            self.app.log(category, message)
        else:
            # Fallback for standalone usage
            print(f"[{category.upper()}] {message}")

    def encrypt(self, plaintext: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """
        Encrypts data and returns: [Nonce (12B)] + [Ciphertext + Tag].
        """
        if not isinstance(plaintext, bytes):
            plaintext = plaintext.encode() if isinstance(plaintext, str) else bytes(plaintext)

        nonce = os.urandom(self.NONCE_SIZE)
        ciphertext_with_tag = self.aes_gcm.encrypt(nonce, plaintext, associated_data)
        
        return nonce + ciphertext_with_tag

    def decrypt(self, encrypted_blob: bytes, associated_data: Optional[bytes] = None) -> Optional[bytes]:
        """
        Decrypts the blob. Returns None on failure.
        """
        if len(encrypted_blob) < self.NONCE_SIZE + self.TAG_SIZE:
            self._log("error", "Decryption failed: Data blob is too short.")
            return None

        nonce = encrypted_blob[:self.NONCE_SIZE]
        ciphertext_with_tag = encrypted_blob[self.NONCE_SIZE:]

        try:
            return self.aes_gcm.decrypt(nonce, ciphertext_with_tag, associated_data)
        except InvalidTag:
            # Crucial for password check feedback
            self._log("security", "Auth Failure: Invalid key or tampered data.")
            return None
        except Exception as e:
            self._log("error", f"Unexpected decryption error: {str(e)}")
            return None

    @staticmethod
    def generate_random_key() -> bytes:
        """Utility to generate a secure 32-byte session key."""
        return os.urandom(32)