import os
from pathlib import Path
from typing import Tuple
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from crypto.encryption import FileEncryptor


class AuthManager:
    """
    Manages the security lifecycle of the application, including password-based 
    vault unlocking, long-term Ed25519 identity management, and ephemeral 
    X25519 key exchanges for Perfect Forward Secrecy (PFS).
    """
    def __init__(self, app, key_dir="keys"):
        self.app = app
        self.key_dir = Path(key_dir)
        self.key_dir.mkdir(parents=True, exist_ok=True)
        
        self.local_encryptor = None
        self.pending_handshakes = {}

    # --- Vault Security (Req 9) ---

    def unlock_vault(self, password: str) -> bool:
        """
        Derives a master key from a user password using PBKDF2-HMAC-SHA256.
        Validates the key by attempting to decrypt a 'verifier' canary file.
        """
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
            iterations=600000,
        )
        master_key = kdf.derive(password.encode())
        potential_encryptor = FileEncryptor(master_key, app=self.app)

        if verifier_path.exists():
            try:
                decrypted = potential_encryptor.decrypt(verifier_path.read_bytes())
                if decrypted == b"VAULT_UNLOCKED":
                    self.local_encryptor = potential_encryptor
                    return True
            except Exception:
                pass
            return False
        else:
            verifier_blob = potential_encryptor.encrypt(b"VAULT_UNLOCKED")
            verifier_path.write_bytes(verifier_blob)
            self.local_encryptor = potential_encryptor
            return True

    # --- Identity Management (Req 2 & 6) ---

    def generate_new_identity(self) -> Tuple[bytes, bytes]:
        """
        Generates a new Ed25519 keypair used for long-term digital signatures 
        and peer identification.
        """
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
        """
        Encrypts the private identity key using the vault's master key 
        before writing it to persistent storage.
        """
        if not self.local_encryptor:
            raise PermissionError("Vault locked.")
        encrypted_key = self.local_encryptor.encrypt(priv_key_bytes)
        (self.key_dir / "id_encrypted.bin").write_bytes(encrypted_key)

    def load_identity_securely(self) -> bytes:
        """
        Attempts to load and decrypt the identity key. If no identity exists 
        or decryption fails, it triggers the generation of a fresh identity.
        """
        path = self.key_dir / "id_encrypted.bin"
        if not self.local_encryptor:
            return None
        
        if not path.exists():
            self.app.log("security", "No identity found. Generating new keys...")
            return self._generate_and_save_fresh_identity()

        try:
            decrypted_key = self.local_encryptor.decrypt(path.read_bytes())
            if decrypted_key and len(decrypted_key) == 32:
                return decrypted_key
            raise ValueError("Invalid key length.")
        except Exception as e:
            self.app.log("error", f"Vault Integrity Error: {e}")
            path.replace(path.with_suffix(".bak"))
            return self._generate_and_save_fresh_identity()

    def _generate_and_save_fresh_identity(self) -> bytes:
        """
        Internal helper to automate the creation and secure storage 
        of a new identity pair.
        """
        priv_bytes, _ = self.generate_new_identity()
        if not self.local_encryptor:
            self.app.log("error", "Cannot save identity: Vault is locked!")
            return None
        self.save_identity_securely(priv_bytes)
        return priv_bytes

    def get_public_key(self) -> bytes:
        """
        Retrieves the public portion of the long-term identity key.
        Used by peers to verify this node's signatures.
        """
        priv_bytes = self.load_identity_securely()
        if not priv_bytes:
            return b"ERROR_KEY"
        priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
        return priv_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    def migrate_identity(self) -> Tuple[bytes, bytes, bytes]:
        """
        Performs a key rotation. Generates a new identity and signs the 
        new public key with the old private key to provide a verifiable 
        chain of trust for peers.
        """
        old_priv_bytes = self.load_identity_securely()
        if not old_priv_bytes:
            raise RuntimeError("Cannot migrate identity: Vault locked or no identity found.")
            
        old_priv = ed25519.Ed25519PrivateKey.from_private_bytes(old_priv_bytes)
        old_pub_bytes = old_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        new_priv_bytes, new_pub_bytes = self.generate_new_identity()
        migration_sig = old_priv.sign(new_pub_bytes)
        self.save_identity_securely(new_priv_bytes)
        
        self.app.log("security", "Identity migrated. Old key invalidated.")
        return old_pub_bytes, new_pub_bytes, migration_sig

    # --- PFS & Mutual Auth (Req 8) ---

    def generate_ephemeral_pair(self) -> Tuple[x25519.X25519PrivateKey, bytes]:
        """
        Creates a one-time use X25519 keypair for a Key Exchange. 
        Discarding this after use ensures Perfect Forward Secrecy.
        """
        priv_key = x25519.X25519PrivateKey.generate()
        pub_bytes = priv_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return priv_key, pub_bytes

    def sign(self, data: bytes) -> bytes:
        """Signs arbitrary data using the long-term Ed25519 identity key."""
        priv_bytes = self.load_identity_securely()
        if not priv_bytes:
            return None
        priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
        return priv_key.sign(data)

    def verify_signature(self, peer_pub_identity: bytes, signature: bytes, data: bytes) -> bool:
        """Verifies that data was signed by the owner of a specific public identity."""
        try:
            pub_key = ed25519.Ed25519PublicKey.from_public_bytes(peer_pub_identity)
            pub_key.verify(signature, data)
            return True
        except Exception:
            self.app.log("error", "Signature verification failed!")
            return False

    def derive_shared_secret(self, peer_ephemeral_bytes: bytes, local_priv_obj) -> bytes:
        """
        Executes an X25519 Diffie-Hellman exchange and runs the result 
        through HKDF to produce a high-entropy symmetric session key.
        """
        peer_pub_obj = x25519.X25519PublicKey.from_public_bytes(peer_ephemeral_bytes)
        raw_secret = local_priv_obj.exchange(peer_pub_obj)
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"p2p-session",
        ).derive(raw_secret)

    def create_encryptor(self, session_key: bytes) -> FileEncryptor:
        """
        Initializes a FileEncryptor instance using a derived session key 
        to secure communication with a peer.
        """
        return FileEncryptor(session_key, app=self.app)