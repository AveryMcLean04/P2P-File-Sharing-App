import os
import json
from pathlib import Path
from typing import Tuple, List, Dict
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from crypto.encryption import FileEncryptor

class AuthManager:
    """Manages identity, vault security, and cryptographic trust."""
    def __init__(self, app, key_dir="keys"):
        self.app = app
        self.key_dir = Path(key_dir)
        self.key_dir.mkdir(parents=True, exist_ok=True)
        self.local_encryptor = None
        self.pending_handshakes = {}

    # --- Vault Security ---

    def unlock_vault(self, password: str) -> bool:
        """Derives master key from password and validates with a canary file."""
        salt_path, verifier_path = self.key_dir / "salt.bin", self.key_dir / "verifier.bin"
        salt = salt_path.read_bytes() if salt_path.exists() else os.urandom(16)
        if not salt_path.exists(): salt_path.write_bytes(salt)

        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600000)
        master_key = kdf.derive(password.encode())
        potential_encryptor = FileEncryptor(master_key, app=self.app)

        if verifier_path.exists():
            try:
                if potential_encryptor.decrypt(verifier_path.read_bytes()) == b"VAULT_UNLOCKED":
                    self.local_encryptor = potential_encryptor
                    return True
            except: pass
            return False
        
        verifier_path.write_bytes(potential_encryptor.encrypt(b"VAULT_UNLOCKED"))
        self.local_encryptor = potential_encryptor
        return True

    # --- Identity & Trust ---

    def sign_manifest(self, file_list: List[Dict]) -> Tuple[bytes, bytes]:
        """Signs a file list to allow off-line verification of file hashes."""
        manifest_bytes = json.dumps(file_list, sort_keys=True).encode()
        return manifest_bytes, self.sign(manifest_bytes)

    def verify_manifest(self, peer_pub_key: bytes, manifest_bytes: bytes, signature: bytes) -> bool:
        """Verifies a file manifest's integrity and origin."""
        return self.verify_signature(peer_pub_key, signature, manifest_bytes)

    def generate_new_identity(self) -> Tuple[bytes, bytes]:
        """Creates a fresh Ed25519 keypair for peer identification."""
        priv = ed25519.Ed25519PrivateKey.generate()
        pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        priv_bytes = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        return priv_bytes, pub

    def save_identity_securely(self, priv_bytes: bytes):
        """Encrypts and stores the private identity key."""
        if not self.local_encryptor: raise PermissionError("Vault locked.")
        (self.key_dir / "id_encrypted.bin").write_bytes(self.local_encryptor.encrypt(priv_bytes))

    def load_identity_securely(self) -> bytes:
        """Decrypts and retrieves the long-term identity key."""
        path = self.key_dir / "id_encrypted.bin"
        if not self.local_encryptor or not path.exists():
            return self._generate_and_save_fresh_identity() if self.local_encryptor else None
        try:
            return self.local_encryptor.decrypt(path.read_bytes())
        except: return self._generate_and_save_fresh_identity()

    def get_public_key(self) -> bytes:
        """Retrieves the public portion of the identity key."""
        priv = self.load_identity_securely()
        if not priv: return b"ERROR"
        return ed25519.Ed25519PrivateKey.from_private_bytes(priv).public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def migrate_identity(self) -> Tuple[bytes, bytes, bytes]:
        """Rotates identity keys and provides a signature of the new key."""
        old_priv_bytes = self.load_identity_securely()
        old_priv = ed25519.Ed25519PrivateKey.from_private_bytes(old_priv_bytes)
        old_pub = old_priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        new_priv, new_pub = self.generate_new_identity()
        sig = old_priv.sign(new_pub)
        self.save_identity_securely(new_priv)
        return old_pub, new_pub, sig

    def sign(self, data: bytes) -> bytes:
        """Signs data using the identity key."""
        priv = self.load_identity_securely()
        return ed25519.Ed25519PrivateKey.from_private_bytes(priv).sign(data) if priv else None

    def verify_signature(self, pub_bytes: bytes, sig: bytes, data: bytes) -> bool:
        """Validates a signature against a public key."""
        try:
            ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes).verify(sig, data)
            return True
        except: return False

    # --- Session Management ---

    def generate_ephemeral_pair(self) -> Tuple[x25519.X25519PrivateKey, bytes]:
        """Creates a one-time X25519 pair for Perfect Forward Secrecy."""
        priv = x25519.X25519PrivateKey.generate()
        pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return priv, pub

    def derive_shared_secret(self, peer_pub_bytes: bytes, local_priv) -> bytes:
        """Derives a symmetric session key via DH and HKDF."""
        shared = local_priv.exchange(x25519.X25519PublicKey.from_public_bytes(peer_pub_bytes))
        return HKDF(hashes.SHA256(), 32, None, b"p2p-session").derive(shared)

    def create_encryptor(self, session_key: bytes) -> FileEncryptor:
        """Initializes a FileEncryptor for a specific peer session."""
        return FileEncryptor(session_key, app=self.app)

    def _generate_and_save_fresh_identity(self) -> bytes:
        priv, _ = self.generate_new_identity()
        self.save_identity_securely(priv)
        return priv