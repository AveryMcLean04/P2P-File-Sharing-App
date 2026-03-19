import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

class FileEncryptor:
    def __init__(self, session_key: bytes):
        """
        Initializes the AES-GCM encryptor.
        
        :param session_key: 32-byte key (AES-256) derived from HKDF.
        """
        if len(session_key) != 32:
            raise ValueError("Session key must be exactly 32 bytes for AES-256-GCM.")
            
        self.aes_gcm = AESGCM(session_key)

    def encrypt_data(self, data_bytes: bytes, associated_data: bytes = None) -> tuple[bytes, bytes]:
        """
        Encrypts data using AES-256-GCM (Requirement 7).
        
        :param data_bytes: The plaintext bytes to encrypt.
        :param associated_data: Optional metadata to authenticate (not encrypted).
        :return: (12-byte nonce, ciphertext_with_16_byte_tag)
        """
        # Requirement 7: 12-byte (96-bit) nonce is the NIST standard for GCM.
        nonce = os.urandom(12)
        
        # The 'encrypt' method automatically appends the 16-byte authentication tag.
        ciphertext = self.aes_gcm.encrypt(nonce, data_bytes, associated_data)
        
        return nonce, ciphertext

    def decrypt_data(self, nonce: bytes, ciphertext_with_tag: bytes, associated_data: bytes = None) -> bytes | None:
        """
        Decrypts and verifies the integrity of the data.
        
        If the tag verification fails (data tampered), cryptography raises InvalidTag.
        
        :param nonce: The 12-byte nonce used during encryption.
        :param ciphertext_with_tag: The encrypted data including the auth tag.
        :param associated_data: Metadata that must match the encryption phase.
        :return: Decrypted bytes if successful, None if integrity check fails.
        """
        try:
            # decrypt() verifies the 16-byte tag before returning any data.
            return self.aes_gcm.decrypt(nonce, ciphertext_with_tag, associated_data)
        
        except InvalidTag:
            # Requirement 7: Integrity check failed.
            print("[!] Security Alert: Integrity check failed. The data has been tampered with.")
            return None
        except Exception as e:
            print(f"[!] Decryption Error: {e}")
            return None