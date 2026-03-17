import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

class KeyManager:
    def __init__(self, keys_dir="data/keys"):
        self.keys_dir = keys_dir
        self.private_key_path = os.path.join(self.keys_dir, "identity_private.pem")
        self.public_key_path = os.path.join(self.keys_dir, "identity_public.pem")
        
        self.private_key = None
        self.public_key = None

    def load_or_generate_keys(self):
        """Loads keys from disk or creates new ones if they don't exist."""
        if os.path.exists(self.private_key_path):
            print("[*] Loading existing identity keys...")
            with open(self.private_key_path, "rb") as f:
                self.private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None, # In a real app, use a password for Req 9
                )
            self.public_key = self.private_key.public_key()
        else:
            print("[!] No keys found. Generating new Ed25519 identity...")
            self.generate_new_keys()

    def generate_new_keys(self):
        """Generates a new Ed25519 key pair (Requirement 6: Migration)."""
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        self.save_keys()

    def save_keys(self):
        """Saves keys to the local filesystem (Requirement 9)."""
        # Save Private Key (PEM format)
        private_bytes = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption() # Change for Req 9 later
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
        
        print(f"[*] Keys saved to {self.keys_dir}")

    def get_public_key_bytes(self):
        """Returns public key in bytes for sharing with peers."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    def sign_message(self, message_bytes):
        """Signs data to prove identity (Requirement 2)."""
        return self.private_key.sign(message_bytes)