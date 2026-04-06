import pytest
from pathlib import Path
from unittest.mock import MagicMock
from src.crypto.secure_disk_store import SecureDiskStore

@pytest.fixture
def store(tmp_path):
    """Initializes SecureDiskStore with temporary vault and shared directories."""
    app_mock = MagicMock()
    encryptor_mock = MagicMock()
    
    encryptor_mock.encrypt.side_effect = lambda x: b"enc_" + x
    encryptor_mock.decrypt.side_effect = lambda x: x.replace(b"enc_", b"")
    encryptor_mock.get_hash.return_value = "mock_hash_123"
    
    vault = tmp_path / "vault"
    shared = tmp_path / "shared"
    
    return SecureDiskStore(str(vault), str(shared), encryptor_mock, app_mock)

# --- Vault Operations ---

def test_save_to_vault_success(store):
    """Success: Save a file and verify the listed name matches the input."""
    filename = "secret.txt"
    content = b"Top Secret Data"
    result = store.save_to_vault(filename, content)
    
    assert result is True
    assert "secret.txt" in store.list_encrypted_files()
    assert (store.vault_dir / "secret.txt.enc").exists()

def test_save_to_vault_fail(store):
    """Fail: Handle write errors gracefully when path is blocked."""
    (store.vault_dir / "error.enc").mkdir()
    result = store.save_to_vault("error.enc", b"data")
    
    assert result is False
    args, _ = store.app.log.call_args
    assert args[0] == "error"
    assert "Vault write failed" in args[1]

def test_load_from_vault_success(store):
    """Success: Retrieve and decrypt a file from the vault."""
    filename = "data.enc"
    (store.vault_dir / "data.enc").write_bytes(b"enc_hello")
    decrypted = store.load_from_vault(filename)
    
    assert decrypted == b"hello"
    store.encryptor.decrypt.assert_called_once()

def test_load_from_vault_fail(store):
    """Fail: Return empty bytes if the file doesn't exist."""
    assert store.load_from_vault("ghost.txt") == b""

# --- Decryption Operations ---

def test_decrypt_to_system_success(store, tmp_path):
    """Success: Decrypt vault file to an external system path."""
    filename = "vault_file.enc"
    (store.vault_dir / filename).write_bytes(b"enc_plaintext_payload")
    
    external_dir = tmp_path / "external_export"
    external_dir.mkdir()
    dest_path = external_dir / "recovered.txt"
    
    result = store.decrypt_to_system(filename, str(dest_path))
    
    assert result is True
    assert dest_path.exists()
    assert dest_path.read_bytes() == b"plaintext_payload"
    store.app.log.assert_any_call("security", f"Successfully decrypted '{filename}' to {dest_path}")

def test_decrypt_to_system_fail(store, tmp_path):
    """Fail: Attempt to decrypt a file that does not exist in the vault."""
    dest_path = tmp_path / "missing_output.txt"
    result = store.decrypt_to_system("non_existent.enc", str(dest_path))
    
    assert result is False
    assert not dest_path.exists()
    
    args, _ = store.app.log.call_args
    assert args[0] == "error"
    assert "Decryption failed" in args[1]

# --- Ingestion & Sharing ---

def test_ingest_file_success(store, tmp_path):
    """Success: Ingest a real local file into vault and shared folders."""
    source_file = tmp_path / "my_photo.jpg"
    content = b"image_binary_data"
    source_file.write_bytes(content)
    
    result = store.ingest_file(str(source_file))
    
    assert result is True
    assert (store.vault_dir / "my_photo.jpg.enc").exists()
    assert (store.shared_dir / "my_photo.jpg").exists()
    assert (store.shared_dir / "my_photo.jpg").read_bytes() == content
    store.app.log.assert_any_call("security", "File 'my_photo.jpg' ingested and ready for sharing.")

def test_ingest_file_fail(store):
    """Fail: Attempt to ingest a non-existent file path."""
    result = store.ingest_file("non_existent_path.txt")
    
    assert result is False
    store.app.log.assert_any_call("error", "Ingest failed: Invalid source 'non_existent_path.txt'")

def test_uningest_file_success(store):
    """Success: Remove file from both directories using consistent naming."""
    filename = "test.txt"
    (store.shared_dir / filename).write_bytes(b"data")
    (store.vault_dir / f"{filename}.enc").write_bytes(b"enc_data")
    
    result = store.uningest_file(filename)
    
    assert result is True
    assert not (store.shared_dir / filename).exists()
    assert not (store.vault_dir / f"{filename}.enc").exists()
    store.app.log.assert_any_call("security", f"Uningested '{filename}'.")

# --- Integrity & Export ---

def test_list_shared_files_success(store):
    """Success: List shared files and verify hash generation."""
    (store.shared_dir / "share_me.txt").write_bytes(b"content")
    shared_list = store.list_shared_files()
    
    assert len(shared_list) == 1
    assert shared_list[0]["filename"] == "share_me.txt"
    assert shared_list[0]["hash"] == "mock_hash_123"
    store.encryptor.get_hash.assert_called_once()

def test_export_from_vault_to_shared_success(store):
    """Success: Export a vault file back to the plaintext shared directory."""
    (store.vault_dir / "vault_item.enc").write_bytes(b"enc_decrypted_content")
    store.export_from_vault_to_shared("vault_item")
    
    shared_file = store.shared_dir / "vault_item"
    assert shared_file.exists()
    assert shared_file.read_bytes() == b"decrypted_content"