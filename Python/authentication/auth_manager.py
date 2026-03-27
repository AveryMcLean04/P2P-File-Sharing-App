import os
import base64
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from crypto.encryption import FileEncryptor 

class AuthManager:
    def __init__(self, app=None, key_dir="keys"):
        self.app = app
        self.key_dir = Path(key_dir)
        self.key_dir.mkdir(parents=True, exist_ok=True)
        
        self.local_encryptor = None
        self.pending_handshakes = {} # Stores {peer_id: local_x25519_priv_obj}

    def _log(self, category: str, message: str):
        if self.app:
            self.app.log(category, message)
        else:
            print(f"[{category.upper()}] {message}")

    # --- Vault Security (Req 9) ---

    def unlock_vault(self, password: str) -> bool:
        """Derives master key and verifies via canary file."""
        salt_path = self.key_dir / "salt.bin"
        verifier_path = self.key_dir / "verifier.bin"

        if salt_path.exists():
            salt = salt_path.read_bytes()
        else:
            salt = os.urandom(16)
            salt_path.write_bytes(salt)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        master_key = kdf.derive(password.encode())
        potential_encryptor = FileEncryptor(master_key, app=self.app)

        if verifier_path.exists():
            decrypted = potential_encryptor.decrypt(verifier_path.read_bytes())
            if decrypted == b"VAULT_UNLOCKED":
                self.local_encryptor = potential_encryptor
                return True
            return False
        else:
            verifier_blob = potential_encryptor.encrypt(b"VAULT_UNLOCKED")
            verifier_path.write_bytes(verifier_blob)
            self.local_encryptor = potential_encryptor
            return True

    # --- Identity Management (Req 2 & 6) ---

    def generate_new_identity(self):
        """Generates long-term Ed25519 identity keypair."""
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

    def save_identity_securely(self, priv_key_bytes: bytes):
        if not self.local_encryptor:
            raise PermissionError("Vault locked.")
        encrypted_key = self.local_encryptor.encrypt(priv_key_bytes)
        (self.key_dir / "id_encrypted.bin").write_bytes(encrypted_key)

    def load_identity_securely(self) -> bytes:
        path = self.key_dir / "id_encrypted.bin"
        
        if not path.exists():
            self._log("system", "No identity found. Generating new keys...")
            return self._generate_and_save_fresh_identity()

        try:
            encrypted_data = path.read_bytes()
            decrypted_key = self.local_encryptor.decrypt(encrypted_data)
            
            if decrypted_key and len(decrypted_key) == 32:
                return decrypted_key
            else:
                raise ValueError("Decrypted key is wrong length or empty.")
                
        except Exception as e:
            self._log("security", f"Vault Integrity Error: {e}")
            self._log("system", "Attempting to recover by generating a fresh identity...")
            
            backup_path = path.with_suffix(".bak")
            path.replace(backup_path)
            
            return self._generate_and_save_fresh_identity()

    def _generate_and_save_fresh_identity(self) -> bytes:
        """Internal helper to ensure we always have a valid 32-byte key."""
        priv_bytes, _ = self.generate_new_identity()
        if not self.local_encryptor:
            self._log("error", "Cannot save identity: Vault is locked!")
            return b""
            
        self.save_identity_securely(priv_bytes)
        return priv_bytes

    def get_public_key(self) -> bytes:
        priv_bytes = self.load_identity_securely()

        if not priv_bytes or len(priv_bytes) != 32:
            self._log("error", "Identity key is invalid. Verification failed.")
            return b"ERROR_KEY"
            
        priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
        return priv_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    def migrate_identity(self):
        """
        Requirement 6: Rotate long-term identity.
        Returns (old_pub, new_pub, migration_signature)
        """
        old_priv_bytes = self.load_identity_securely()
        old_priv = ed25519.Ed25519PrivateKey.from_private_bytes(old_priv_bytes)
        old_pub_bytes = old_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        new_priv_bytes, new_pub_bytes = self.generate_new_identity()
        migration_sig = old_priv.sign(new_pub_bytes)
        self.save_identity_securely(new_priv_bytes)
        
        self._log("security", "Identity migrated. Old key invalidated.")
        return old_pub_bytes, new_pub_bytes, migration_sig

    # --- PFS & Mutual Auth (Req 8) ---

    def generate_ephemeral_pair(self):
        """Returns (Private_Object, Public_Bytes) for X25519."""
        priv_key = x25519.X25519PrivateKey.generate()
        pub_bytes = priv_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return priv_key, pub_bytes

    def sign(self, data: bytes) -> bytes:
        """Signs data using long-term Ed25519 key for authentication."""
        priv_bytes = self.load_identity_securely()
        priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
        return priv_key.sign(data)

    def verify_signature(self, peer_pub_identity: bytes, signature: bytes, data: bytes) -> bool:
        """Requirement 2: Verifies that the peer actually owns their identity key."""
        try:
            pub_key = ed25519.Ed25519PublicKey.from_public_bytes(peer_pub_identity)
            pub_key.verify(signature, data)
            return True
        except Exception:
            self._log("security", "Signature verification failed! Potential impersonation.")
            return False

    def derive_shared_secret(self, peer_ephemeral_bytes: bytes, local_priv_obj) -> bytes:
        """DH Exchange + HKDF for 32-byte AES key."""
        peer_pub_obj = x25519.X25519PublicKey.from_public_bytes(peer_ephemeral_bytes)
        raw_secret = local_priv_obj.exchange(peer_pub_obj)
        
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"p2p-session",
        ).derive(raw_secret)

    def create_encryptor(self, session_key: bytes) -> FileEncryptor:
        """Utility to turn a derived key into a usable FileEncryptor."""
        return FileEncryptor(session_key, app=self.app)