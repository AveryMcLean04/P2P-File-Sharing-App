import os
import logging
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("FileEncryptor")

class FileEncryptor:
    NONCE_SIZE = 12

    def __init__(self, session_key: bytes):
        """
        Initializes the AES-256-GCM encryptor.
        :param session_key: 32-byte key (AES-256).
        """
        if len(session_key) != 32:
            raise ValueError("Key must be 32 bytes (256 bits).")
        self.aes_gcm = AESGCM(session_key)

    def encrypt(self, plaintext: bytes, associated_data: bytes = None) -> bytes:
        """
        Encrypts data and returns a combined (nonce + ciphertext + tag) byte string.
        """
        nonce = os.urandom(self.NONCE_SIZE)
        ciphertext = self.aes_gcm.encrypt(nonce, plaintext, associated_data)
        
        return nonce + ciphertext

    def decrypt(self, encrypted_blob: bytes, associated_data: bytes = None) -> bytes | None:
        """
        Unpacks the blob and decrypts. Returns None if integrity check fails.
        """
        if len(encrypted_blob) < self.NONCE_SIZE + 16:
            logger.error("Data blob is too short to be valid.")
            return None

        nonce = encrypted_blob[:self.NONCE_SIZE]
        ciphertext = encrypted_blob[self.NONCE_SIZE:]

        try:
            return self.aes_gcm.decrypt(nonce, ciphertext, associated_data)
        except InvalidTag:
            logger.warning("Security Alert: Integrity check failed. Data tampered!")
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
        
        return None