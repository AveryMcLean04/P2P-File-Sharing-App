from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

class SessionManager:
    def __init__(self):
        """
        Requirement 5: Perfect Forward Secrecy (PFS).
        Generates a one-time ephemeral X25519 key pair for this specific session.
        """
        self.private_key = x25519.X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        self.shared_key = None

    def get_public_bytes(self) -> bytes:
        """Returns the ephemeral public key in raw format (32 bytes)."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    def sign_ephemeral_key(self, identity_private_key: ed25519.Ed25519PrivateKey) -> bytes:
        """
        Requirement 2: Authentication.
        Signs the ephemeral key using the long-term identity key to prevent MitM.
        """
        return identity_private_key.sign(self.get_public_bytes())

    def verify_peer_signature(self, peer_identity_pub_key: ed25519.Ed25519PublicKey, 
                              peer_ephemeral_bytes: bytes, 
                              signature: bytes) -> bool:
        """
        Requirement 2: Verification.
        Ensures the peer's ephemeral key was signed by their trusted identity key.
        """
        try:
            peer_identity_pub_key.verify(signature, peer_ephemeral_bytes)
            return True
        except (InvalidSignature, Exception):
            return False

    def derive_shared_secret(self, peer_public_bytes: bytes, salt: bytes = None) -> bytes:
        """
        Requirement 5 & 7: Key Exchange & Derivation.
        Combines X25519 DH exchange with HKDF to produce a high-entropy 256-bit key.
        
        :param peer_public_bytes: The 32-byte ephemeral key from the peer.
        :param salt: Optional random bytes to add uniqueness to the KDF.
        """
        # 1. Perform X25519 Diffie-Hellman Exchange
        peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
        raw_shared_secret = self.private_key.exchange(peer_public_key)

        # 2. Requirement 7: HKDF with SHA-256 for key expansion
        # We use 'session_key' as the info context to bind the key to this app logic.
        self.shared_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"p2p_file_share_session_v1",
        ).derive(raw_shared_secret)
        
        return self.shared_key