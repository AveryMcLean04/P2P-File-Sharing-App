import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class FileEncryptor:
    def __init__(self, session_key):
        """
        session_key: The 32-byte key derived from HKDF in SessionManager.
        """
        self.aes_gcm = AESGCM(session_key)

    def encrypt_data(self, data_bytes):
        """
        Encrypts data using AES-256-GCM (Requirement 7).
        Returns: (nonce, ciphertext_with_tag)
        """
        # GCM requires a unique nonce (IV) for every single message.
        # Requirement 7: 12-byte (96-bit) nonce is standard for GCM.
        nonce = os.urandom(12)
        
        # The 'encrypt' method in cryptography library handles adding 
        # the 16-byte authentication tag automatically.
        ciphertext = self.aes_gcm.encrypt(nonce, data_bytes, None)
        
        return nonce, ciphertext

    def decrypt_data(self, nonce, ciphertext_with_tag):
        """
        Decrypts data. If the data was tampered with, this will raise an 
        InvalidTag exception, satisfying Requirement 7's Integrity check.
        """
        try:
            decrypted_data = self.aes_gcm.decrypt(nonce, ciphertext_with_tag, None)
            return decrypted_data
        except Exception as e:
            print(f"[!] Decryption/Integrity failure: {e}")
            return None