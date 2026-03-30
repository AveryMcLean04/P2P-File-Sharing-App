import pytest
import os
from pathlib import Path
from unittest.mock import MagicMock, ANY
from crypto.encryption import FileEncryptor
from crypto.secure_disk_store import SecureDiskStore

# --- 1. FileEncryptor Tests ---

def test_encryptor_initialization(mock_app):
    valid_key = os.urandom(32)
    encryptor = FileEncryptor(valid_key, mock_app)
    assert encryptor.NONCE_SIZE == 12

def test_encryption_decryption_cycle(mock_app):
    key = FileEncryptor.generate_random_key()
    encryptor = FileEncryptor(key, mock_app)
    original_data = b"Secret Message 123"
    encrypted_blob = encryptor.encrypt(original_data)
    decrypted_data = encryptor.decrypt(encrypted_blob)
    assert decrypted_data == original_data

def test_decryption_tamper_failure(mock_app):
    key = FileEncryptor.generate_random_key()
    encryptor = FileEncryptor(key, mock_app)
    blob = list(encryptor.encrypt(b"Genuine Data"))
    blob[20] ^= 0xFF 
    tampered_blob = bytes(blob)
    assert encryptor.decrypt(tampered_blob) is None
    mock_app.log.assert_called_with("error", ANY)

# --- 2. SecureDiskStore Tests ---

@pytest.fixture
def storage_setup(tmp_path, mock_app):
    vault_dir = tmp_path / "vault"
    shared_dir = tmp_path / "shared"
    
    mock_app.discovery = MagicMock()
    mock_app.network = MagicMock()
    mock_app.active_sessions = {}
    mock_app.user_id = "test_user"
    
    key = os.urandom(32)
    encryptor = FileEncryptor(key, mock_app)
    store = SecureDiskStore(str(vault_dir), str(shared_dir), encryptor, mock_app)
    return store, vault_dir, shared_dir

def test_store_save_and_load_vault(storage_setup):
    store, vault_dir, _ = storage_setup
    filename = "test.txt"
    content = b"Hello Vault"
    
    success = store.save_to_vault(filename, content)
    
    assert success is True
    assert (vault_dir / "test.txt.enc").exists()
    
    loaded = store.load_from_vault("test.txt")
    assert loaded == content

def test_ingest_file_workflow(storage_setup, tmp_path):
    store, vault_dir, shared_dir = storage_setup
    src_file = tmp_path / "data.dat"
    src_file.write_bytes(b"some data")

    success = store.ingest_file(str(src_file))
    
    assert success is True
    assert (vault_dir / "data.dat.enc").exists()
    assert (shared_dir / "data.dat").exists()

def test_uningest_file_cleanup(storage_setup):
    store, vault_dir, shared_dir = storage_setup
    
    filename = "note.txt"
    (shared_dir / filename).write_bytes(b"plain")
    (vault_dir / "note.txt.enc").write_bytes(b"encrypted")
    
    store.app.active_sessions = {"peer1": {}}
    store.app.discovery.peers = {"peer1": {"ip": "127.0.0.1", "port": 5000}}

    success = store.uningest_file(filename)
    
    assert success is True
    assert not (shared_dir / filename).exists()
    assert not (vault_dir / "note.txt.enc").exists()

def test_load_nonexistent_file_failure(storage_setup):
    store, _, _ = storage_setup
    result = store.load_from_vault("ghost.txt")
    assert result == b""
    store.app.log.assert_called_with("error", ANY)