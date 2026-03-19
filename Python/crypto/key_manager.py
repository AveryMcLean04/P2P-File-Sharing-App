import os
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

class KeyManager:
    def __init__(self, keys_dir="data/keys", password: str = None):
        """
        keys_dir: Directory where identity keys are stored.
        password: String used to encrypt/decrypt the private key on disk (Requirement 9).
        """
        self.keys_dir = Path(keys_dir)
        self.private_key_path = self.keys_dir / "identity_private.pem"
        self.public_key_path = self.keys_dir / "identity_public.pem"
        
        # Convert password to bytes if provided
        self.password = password.encode() if password else None
        
        self.private_key = None
        self.public_key = None

    def load_or_generate_keys(self):
        """Loads keys from disk or creates new ones if they don't exist."""
        self.keys_dir.mkdir(parents=True, exist_ok=True)

        if self.private_key_path.exists():
            try:
                with open(self.private_key_path, "rb") as f:
                    self.private_key = serialization.load_pem_private_key(
                        f.read(),
                        password=self.password,  # Requirement 9: Secure storage
                    )
                self.public_key = self.private_key.public_key()
                print("[*] Identity keys loaded successfully.")
            except (ValueError, TypeError):
                print("[!] Error: Incorrect password or corrupted key file.")
                raise
        else:
            print("[!] No keys found. Generating new Ed25519 identity...")
            self.generate_new_keys()

    def generate_new_keys(self):
        """Generates a new Ed25519 key pair (Requirement 6: Migration/Rotation)."""
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        self.save_keys()

    def save_keys(self):
        """Saves keys to the local filesystem using encryption (Requirement 9)."""
        # Determine encryption algorithm for storage
        if self.password:
            # Uses AES-256-CBC with a derived key (Standard for PEM encryption)
            encryption_algo = serialization.BestAvailableEncryption(self.password)
        else:
            print("[#] Warning: Saving private key without encryption!")
            encryption_algo = serialization.NoEncryption()

        # Save Private Key (PEM format)
        private_bytes = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algo
        )
        
        # Save Public Key (PEM format)
        public_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open(self.private_key_path, "wb") as f:
            f.write(private_bytes)
        with open(self.public_key_path, "wb") as f:
            f.write(public_bytes)
        
        print(f"[*] Keys securely saved to {self.keys_dir}")

    def get_public_key_bytes(self, raw=True):
        """
        Returns public key bytes for sharing.
        raw=True: 32-byte raw format for Ed25519.
        raw=False: SubjectPublicKeyInfo (PEM-ready).
        """
        if raw:
            return self.public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def sign_message(self, message_bytes: bytes) -> bytes:
        """Signs data to prove identity (Requirement 2: Authentication)."""
        if not self.private_key:
            raise RuntimeError("Private key not loaded.")
        return self.private_key.sign(message_bytes)

    def sign_data(self, data: bytes) -> bytes:
        return self.sign_message(data)

    def verify_peer_signature(self, peer_public_key_bytes: bytes, message: bytes, signature: bytes) -> bool:
        """Helper to verify a peer's identity signature."""
        try:
            peer_pub = ed25519.Ed25519PublicKey.from_public_bytes(peer_public_key_bytes)
            peer_pub.verify(signature, message)
            return True
        except Exception:
            return False