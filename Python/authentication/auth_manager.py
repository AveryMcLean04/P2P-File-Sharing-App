import os
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Assuming your FileEncryptor is in crypto.encryption
from crypto.encryption import FileEncryptor 

class AuthManager:
    def __init__(self, key_dir="keys"):
        self.key_dir = Path(key_dir)
        self.key_dir.mkdir(parents=True, exist_ok=True)
        
        self.local_encryptor = None
        self.pending_handshakes = {}
        
    def unlock_vault(self, password: str) -> bool:
        """
        Requirement 9: Derives a master key from a password and 
        verifies it against a 'verifier.bin' (canary) file.
        """
        salt_path = self.key_dir / "salt.bin"
        verifier_path = self.key_dir / "verifier.bin"

        # 1. Handle Salt (Create if missing)
        if salt_path.exists():
            salt = salt_path.read_bytes()
        else:
            salt = os.urandom(16)
            salt_path.write_bytes(salt)

        # 2. Derive Key using PBKDF2
        # 600,000 iterations is the 2026 standard for SHA-256
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        master_key = kdf.derive(password.encode())
        potential_encryptor = FileEncryptor(master_key)

        # 3. Password Verification (The "Canary" Check)
        if verifier_path.exists():
            encrypted_verifier = verifier_path.read_bytes()
            # If the password is wrong, FileEncryptor.decrypt returns None
            decrypted = potential_encryptor.decrypt(encrypted_verifier)
            
            if decrypted == b"VAULT_UNLOCKED":
                self.local_encryptor = potential_encryptor
                return True
            else:
                return False # Incorrect password
        else:
            # First-time setup: Create the verifier file
            verifier_blob = potential_encryptor.encrypt(b"VAULT_UNLOCKED")
            verifier_path.write_bytes(verifier_blob)
            self.local_encryptor = potential_encryptor
            return True

    def save_identity_securely(self, priv_key_bytes: bytes):
        """Encrypts the private identity key before writing to disk."""
        if not self.local_encryptor:
            raise PermissionError("Vault not unlocked. Call unlock_vault first.")
            
        encrypted_key = self.local_encryptor.encrypt(priv_key_bytes)
        (self.key_dir / "id_encrypted.bin").write_bytes(encrypted_key)

    def load_identity_securely(self) -> bytes:
        """Requirement 2 & 9: Decrypts the private identity key or creates it if missing."""
        path = self.key_dir / "id_encrypted.bin"
        
        if not path.exists():
            print("[*] No identity found. Generating new long-term keys...")
            priv_bytes, _ = self.generate_new_identity()
            self.save_identity_securely(priv_bytes)
            return priv_bytes

        encrypted_data = path.read_bytes()
        decrypted_key = self.local_encryptor.decrypt(encrypted_data)
        
        if decrypted_key is None:
            raise ValueError("Integrity failure: Cannot decrypt identity. Check password.")
            
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

    def get_public_key(self) -> bytes:
        """Returns the public identity key from the saved private key."""
        priv_bytes = self.load_identity_securely()
        priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
        return priv_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    def generate_ephemeral_share(self) -> bytes:
        """Requirement 8: Generate a temporary X25519 public key for PFS."""
        self.temp_priv = x25519.X25519PrivateKey.generate()
        return self.temp_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    def derive_shared_secret(self, peer_pub_bytes: bytes, local_priv_obj) -> bytes:
        """Requirement 8: DH Key Exchange + HKDF for session key."""
        peer_pub_obj = x25519.X25519PublicKey.from_public_bytes(peer_pub_bytes)
        raw_secret = local_priv_obj.exchange(peer_pub_obj)
        
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"p2p-session",
        ).derive(raw_secret)

    def sign(self, data: bytes) -> bytes:
        """Signs data using long-term Ed25519 key."""
        priv_bytes = self.load_identity_securely()
        priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
        return priv_key.sign(data)