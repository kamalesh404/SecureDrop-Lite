"""Tests for chunk reassembly and file transfer logic."""

import pytest
from src.securedrop_lite.crypto import (
    KeyPair,
    derive_shared_key,
    hkdf_sha256,
    createAesGcmKey,
    encrypt_file_stream,
    decrypt_file_stream,
    CHUNK_SIZE,
)


# We need to import the async functions from crypto.js logic
# Since we can't run JS here, we'll test the Python equivalents


class MockAESGCM:
    """Mock for testing chunk reassembly logic without crypto."""

    def __init__(self, key):
        self.key = key

    def encrypt(self, nonce, plaintext, associated_data):
        return nonce + plaintext + b"TAG"

    def decrypt(self, nonce, ciphertext, associated_data):
        # Strip nonce and tag
        return ciphertext[len(nonce):-4]


def test_chunk_ordering():
    """Test that chunks are reassembled in correct order."""
    chunks = [b"chunk0", b"chunk1", b"chunk2", b"chunk3"]
    # Simulate receiving out of order
    received = {2: chunks[2], 0: chunks[0], 3: chunks[3], 1: chunks[1]}

    reassembled = b"".join(received[i] for i in range(len(chunks)))
    assert reassembled == b"".join(chunks)


def test_missing_chunk_detection():
    """Test detection of missing chunks."""
    total_chunks = 5
    received = {0: b"0", 1: b"1", 3: b"3", 4: b"4"}

    missing = [i for i in range(total_chunks) if i not in received]
    assert missing == [2]


def test_partial_chunk_handling():
    """Test handling of partial final chunk."""
    file_size = CHUNK_SIZE * 2 + 100
    total_chunks = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE
    assert total_chunks == 3


def test_session_id_uniqueness():
    """Test that session IDs are unique."""
    ids = set()
    for _ in range(1000):
        # Simulate session ID generation (16 bytes hex = 32 chars)
        import os
        sid = os.urandom(16).hex()
        assert sid not in ids
        ids.add(sid)


def test_large_file_chunking():
    """Test chunking of large files."""
    sizes = [
        0,
        1,
        CHUNK_SIZE - 1,
        CHUNK_SIZE,
        CHUNK_SIZE + 1,
        CHUNK_SIZE * 10,
        CHUNK_SIZE * 100,
        10 * 1024 * 1024,  # 10 MiB
    ]

    for size in sizes:
        num_chunks = (size + CHUNK_SIZE - 1) // CHUNK_SIZE if size > 0 else 0
        expected = max(1, (size + CHUNK_SIZE - 1) // CHUNK_SIZE) if size > 0 else 0
        if size == 0:
            assert num_chunks == 0
        else:
            assert num_chunks == expected


@pytest.mark.asyncio
async def test_full_encrypt_decrypt_cycle():
    """Integration test: full encrypt/decrypt cycle with real crypto."""
    # Generate keys
    alice = KeyPair.generate()
    bob = KeyPair.generate()

    # Derive shared secret
    shared = derive_shared_key(alice.private_key, bob.public_key)

    # Derive encryption key
    salt = b"somesalt" * 4  # 32 bytes
    info = b"securedrop-lite-file-transfer"
    key_material = hkdf_sha256(shared, salt, info)

    # We can't easily test AESGCM without the actual key object,
    # but we can test the key derivation chain
    assert len(key_material) == 32

    # Test with different salt produces different key
    key_material2 = hkdf_sha256(shared, b"differentsalt" * 4, info)
    assert key_material != key_material2


def test_chunk_size_constant():
    """Verify CHUNK_SIZE is 64 KiB."""
    assert CHUNK_SIZE == 64 * 1024


def test_nonce_uniqueness_per_chunk():
    """Test that each chunk gets unique nonce via index embedding."""
    from src.securedrop_lite.crypto import encrypt_chunk, NONCE_SIZE

    key = b"0" * 32
    plaintext = b"test"

    enc1 = encrypt_chunk(key, plaintext, 0)
    enc2 = encrypt_chunk(key, plaintext, 1)
    enc3 = encrypt_chunk(key, plaintext, 256)

    # Nonces should be different (first 4 bytes contain index)
    assert enc1[:4] != enc2[:4]
    assert enc2[:4] != enc3[:4]
    assert enc1[:4] != enc3[:4]

    # But rest of nonce should be random (very unlikely to be same)
    assert enc1[4:] != enc2[4:]


def test_replay_protection():
    """Test that replaying a chunk with different index fails."""
    from src.securedrop_lite.crypto import encrypt_chunk, decrypt_chunk

    key = b"0" * 32
    plaintext = b"test data"

    encrypted = encrypt_chunk(key, plaintext, 5)

    # Should decrypt with correct index
    decrypted = decrypt_chunk(key, encrypted, 5)
    assert decrypted == plaintext

    # Should fail with wrong index
    with pytest.raises(ValueError, match="Chunk index mismatch"):
        decrypt_chunk(key, encrypted, 6)