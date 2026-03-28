import os
from typing import Tuple, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


class FileEncryptor:
    """
    Provides Authenticated Encryption with Associated Data (AEAD) using AES-256-GCM.
    Ensures both confidentiality and integrity of the data.
    """
    
    NONCE_SIZE = 12
    TAG_SIZE = 16

    def __init__(self, key: bytes, app):
        """
        Initializes the AES-256-GCM instance.
        
        :param key: A 32-byte (256-bit) symmetric key.
        :param app: The application instance for logging.
        """
        if len(key) != 32:
            raise ValueError("AES-256 requires a 32-byte key.")
            
        self.aes_gcm = AESGCM(key)
        self.app = app

    def encrypt(self, plaintext: bytes, associated_data: bytes = None) -> bytes:
        """
        Encrypts plaintext and prepends a random 12-byte nonce.
        Layout: [Nonce (12B)] + [Ciphertext] + [Auth Tag (16B)]
        
        :param plaintext: The data to encrypt (bytes or str).
        :param associated_data: Optional metadata to authenticate but not encrypt.
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()
        elif not isinstance(plaintext, bytes):
            plaintext = bytes(plaintext)

        nonce = os.urandom(self.NONCE_SIZE)
        ciphertext_with_tag = self.aes_gcm.encrypt(nonce, plaintext, associated_data)
        
        return nonce + ciphertext_with_tag

    def decrypt(self, encrypted_blob: bytes, associated_data: bytes = None) -> bytes:
        """
        Separates the nonce from the blob and decrypts the remainder.
        The GCM algorithm automatically verifies the 16-byte authentication tag.
        
        :return: Decrypted bytes if successful, None if verification or decryption fails.
        """
        if len(encrypted_blob) < self.NONCE_SIZE + self.TAG_SIZE:
            self.app.log("error", "Decryption failed: Data blob is too short.")
            return None

        nonce = encrypted_blob[:self.NONCE_SIZE]
        ciphertext_with_tag = encrypted_blob[self.NONCE_SIZE:]

        try:
            return self.aes_gcm.decrypt(nonce, ciphertext_with_tag, associated_data)
        except InvalidTag:
            self.app.log("security", "Auth Failure: Invalid key or tampered data.")
            return None
        except Exception as e:
            self.app.log("error", f"Unexpected decryption error: {str(e)}")
            return None

    @staticmethod
    def generate_random_key() -> bytes:
        """
        Generates a cryptographically secure 32-byte key suitable for AES-256.
        """
        return os.urandom(32)