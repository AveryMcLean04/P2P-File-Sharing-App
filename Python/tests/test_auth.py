import pytest
import os
from unittest.mock import MagicMock, patch
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519

# --- SUCCESS CASES ---

def test_vault_initialization_and_unlock(tmp_path):
    """SUCCESS: Verify vault creates a verifier and unlocks with the correct password."""
    import authentication.auth_manager as auth
    
    # Setup mock app and directory
    mock_app = MagicMock()
    key_dir = tmp_path / "keys"
    manager = auth.AuthManager(mock_app, key_dir=key_dir)
    
    # 1. First unlock creates the verifier
    password = "secure_password"
    assert manager.unlock_vault(password) is True
    assert (key_dir / "salt.bin").exists()
    assert (key_dir / "verifier.bin").exists()
    
    # 2. Subsequent unlock with same password works
    new_manager = auth.AuthManager(mock_app, key_dir=key_dir)
    assert new_manager.unlock_vault(password) is True
    assert new_manager.local_encryptor is not None

def test_identity_lifecycle(mock_app, tmp_path):
    """SUCCESS: Verify identity can be generated, saved, and reloaded."""
    from authentication.auth_manager import AuthManager
    
    manager = AuthManager(mock_app, key_dir=tmp_path)
    manager.unlock_vault("test") # Initialize local_encryptor
    
    # Generate and save
    priv_bytes = manager.load_identity_securely() # Triggers generation if missing
    assert len(priv_bytes) == 32
    
    # Verify public key retrieval
    pub_bytes = manager.get_public_key()
    assert len(pub_bytes) == 32
    
    # Verify persistence
    assert (tmp_path / "id_encrypted.bin").exists()

def test_pfs_key_exchange_primitives(mock_app):
    """SUCCESS: Verify X25519 ephemeral exchange and HKDF derivation."""
    from authentication.auth_manager import AuthManager
    manager = AuthManager(mock_app)
    
    # Generate Alice's ephemeral pair
    alice_priv, alice_pub = manager.generate_ephemeral_pair()
    
    # Generate Bob's ephemeral pair
    bob_priv, bob_pub = manager.generate_ephemeral_pair()
    
    # Both derive the same secret
    secret_alice = manager.derive_shared_secret(bob_pub, alice_priv)
    secret_bob = manager.derive_shared_secret(alice_pub, bob_priv)
    
    assert secret_alice == secret_bob
    assert len(secret_alice) == 32

# --- FAILURE CASES ---

def test_vault_wrong_password_failure(tmp_path):
    """FAILURE: Verify vault rejects incorrect passwords."""
    import authentication.auth_manager as auth
    mock_app = MagicMock()
    key_dir = tmp_path / "keys"
    
    manager = auth.AuthManager(mock_app, key_dir=key_dir)
    manager.unlock_vault("correct_password")
    
    # Try with wrong password
    fail_manager = auth.AuthManager(mock_app, key_dir=key_dir)
    assert fail_manager.unlock_vault("wrong_password") is False
    assert fail_manager.local_encryptor is None

def test_identity_load_without_unlock_failure(tmp_path):
    """FAILURE: Verify identity cannot be loaded if the vault is locked."""
    from authentication.auth_manager import AuthManager
    mock_app = MagicMock()
    manager = AuthManager(mock_app, key_dir=tmp_path)
    
    # Do not call unlock_vault
    assert manager.load_identity_securely() is None

def test_signature_verification_tamper_failure(mock_app):
    """FAILURE: Verify that tampered data fails signature verification."""
    from authentication.auth_manager import AuthManager
    manager = AuthManager(mock_app)
    manager.unlock_vault("test")
    
    data = b"Original Message"
    pub_key = manager.get_public_key()
    sig = manager.sign(data)
    
    tampered_data = b"Tampered Message"
    assert manager.verify_signature(pub_key, sig, tampered_data) is False

def test_identity_migration_chain_of_trust(mock_app, tmp_path):
    """SUCCESS: Verify key rotation produces a valid signature of the new key."""
    from authentication.auth_manager import AuthManager
    manager = AuthManager(mock_app, key_dir=tmp_path)
    manager.unlock_vault("test")
    
    # Initial identity
    old_pub = manager.get_public_key()
    
    # Rotate
    returned_old_pub, new_pub, migration_sig = manager.migrate_identity()
    
    assert returned_old_pub == old_pub
    # Verify: Old key signed the new key
    assert manager.verify_signature(old_pub, migration_sig, new_pub) is True