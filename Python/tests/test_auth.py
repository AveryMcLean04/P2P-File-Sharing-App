import pytest
import os
from pathlib import Path
from unittest.mock import MagicMock, patch
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from src.authentication.auth_manager import AuthManager

@pytest.fixture
def auth_mgr(tmp_path):
    """Initializes AuthManager with a temporary key directory."""
    app_mock = MagicMock()
    key_dir = tmp_path / "keys"
    return AuthManager(app_mock, key_dir=str(key_dir))

def get_valid_ed25519_priv_bytes():
    """Generates a valid 32-byte Ed25519 private seed."""
    priv = ed25519.Ed25519PrivateKey.generate()
    return priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )

# --- Identity & Signing Tests ---

def test_sign_and_verify(auth_mgr):
    """Success: Sign data and verify it with the public key."""
    seed = get_valid_ed25519_priv_bytes()
    expected_pub = ed25519.Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    
    with patch.object(AuthManager, 'load_identity_securely', return_value=seed):
        data = b"Hello P2P"
        
        signature = auth_mgr.sign(data)
        assert signature is not None
        
        is_valid = auth_mgr.verify_signature(expected_pub, signature, data)
        assert is_valid is True

def test_verify_signature_fail(auth_mgr):
    """Fail: Verify fails with tampered data."""
    seed = get_valid_ed25519_priv_bytes()
    expected_pub = ed25519.Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    
    with patch.object(AuthManager, 'load_identity_securely', return_value=seed):
        data = b"Original Data"
        sig = auth_mgr.sign(data)
        
        assert auth_mgr.verify_signature(expected_pub, sig, b"Tampered Data") is False

def test_get_public_key_error_handling(auth_mgr):
    """Fail: Handle cases where identity cannot be loaded."""
    with patch.object(AuthManager, 'load_identity_securely', return_value=None):
        pub_key = auth_mgr.get_public_key()
        assert pub_key == b"ERROR"

# --- Session Management Tests ---

def test_derive_shared_secret(auth_mgr):
    """Success: Verify Diffie-Hellman exchange and HKDF derivation."""
    priv_a, pub_a = auth_mgr.generate_ephemeral_pair()
    priv_b, pub_b = auth_mgr.generate_ephemeral_pair()
    
    secret_a = auth_mgr.derive_shared_secret(pub_b, priv_a)
    secret_b = auth_mgr.derive_shared_secret(pub_a, priv_b)
    
    assert secret_a == secret_b
    assert len(secret_a) == 32