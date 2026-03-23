import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from crypto.encryption import FileEncryptor 

class AuthManager:
    def __init__(self, key_dir="keys"):
        self.key_dir = key_dir
        self.local_encryptor = None
        self.pending_handshakes = {}
        
    def unlock_vault(self, password: str):
        """
        Requirement 9: Derives a local master key from a password 
        to encrypt/decrypt local keys and files.
        """
        salt_path = os.path.join(self.key_dir, "salt.bin")
        if os.path.exists(salt_path):
            with open(salt_path, "rb") as f:
                salt = f.read()
        else:
            salt = os.urandom(16)
            with open(salt_path, "wb") as f:
                f.write(salt)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        master_key = kdf.derive(password.encode())
        self.local_encryptor = FileEncryptor(master_key)
        
    def save_identity_securely(self, priv_key_bytes: bytes):
        """Encrypts the private identity key before writing to disk."""
        if not self.local_encryptor:
            raise PermissionError("Vault not unlocked with password.")
            
        encrypted_key = self.local_encryptor.encrypt(priv_key_bytes)
        with open(os.path.join(self.key_dir, "id_encrypted.bin"), "wb") as f:
            f.write(encrypted_key)

    def load_identity_securely(self) -> bytes:
        """Requirement 2 & 9: Decrypts the private identity key or creates it if missing."""
        path = os.path.join(self.key_dir, "id_encrypted.bin")
        
        # 1. Check if the file exists
        if not os.path.exists(path):
            print("[*] No identity found. Generating new long-term keys...")
            # Generate new Ed25519 identity keys
            priv_bytes, _ = self.generate_new_identity()
            # Save them securely using the password-derived local_encryptor
            self.save_identity_securely(priv_bytes)
            return priv_bytes

        # 2. If it does exist, proceed with decryption
        with open(path, "rb") as f:
            encrypted_data = f.read()
        
        decrypted_key = self.local_encryptor.decrypt(encrypted_data)
        if decrypted_key is None:
            raise ValueError("Failed to decrypt identity. Wrong password or tampered file.")
            
        return decrypted_key

    def generate_new_identity(self):
        """Requirement 6: Generate a new long-term Ed25519 identity keypair."""
        priv_key = ed25519.Ed25519PrivateKey.generate()
        pub_key = priv_key.public_key()
        
        priv_bytes = priv_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        pub_bytes = pub_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return priv_bytes, pub_bytes

    def get_public_key(self):
        """Returns the public identity key from the saved private key."""
        priv_bytes = self.load_identity_securely()
        priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
        return priv_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    def generate_ephemeral_share(self):
        """Requirement 8: Generate a temporary X25519 key for PFS."""
        # We use X25519 for Diffie-Hellman (key exchange) 
        # while Ed25519 is used for Identity (signing).
        self.temp_priv = x25519.X25519PrivateKey.generate()
        return self.temp_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    def generate_ephemeral_pair(self):
        """Generates a temporary X25519 pair."""
        priv = x25519.X25519PrivateKey.generate()
        pub = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return priv, pub

    def derive_shared_secret(self, peer_pub_bytes: bytes, local_priv_obj):
        """Requirement 8: DH Key Exchange + HKDF for session key."""
        peer_pub_obj = x25519.X25519PublicKey.from_public_bytes(peer_pub_bytes)
        raw_secret = local_priv_obj.exchange(peer_pub_obj)
        
        # Turn raw DH secret into a 32-byte session key
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"p2p-session",
        ).derive(raw_secret)

    def create_encryptor(self, key: bytes):
        """Instantiates the FileEncryptor the CLI expects."""
        return FileEncryptor(key)

    def sign(self, data: bytes) -> bytes:
        """Signs data using long-term Ed25519 key."""
        priv_bytes = self.load_identity_securely()
        priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
        return priv_key.sign(data)