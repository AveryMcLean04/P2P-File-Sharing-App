from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization

class SessionManager:
    def __init__(self):
        self.private_key = x25519.X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        self.shared_key = None

    def get_public_bytes(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    def sign_ephemeral_key(self, identity_private_key):
        """Requirement 2: Sign the ephemeral key to prove identity."""
        return identity_private_key.sign(self.get_public_bytes())

    def verify_peer_signature(self, peer_identity_public_key, peer_ephemeral_bytes, signature):
        """Requirement 2: Verify the peer actually owns their identity key."""
        try:
            peer_identity_public_key.verify(signature, peer_ephemeral_bytes)
            return True
        except Exception:
            return False

    def derive_shared_secret(self, peer_public_bytes):
        peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
        raw_shared_secret = self.private_key.exchange(peer_public_key)

        self.shared_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"session_key",
        ).derive(raw_shared_secret)
        return self.shared_key