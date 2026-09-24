"""Tests for crypto module."""

import pytest
from src.securedrop_lite.crypto import (
    KeyPair,
    derive_shared_key,
    hkdf_sha256,
    encrypt_chunk,
    decrypt_chunk,
    encrypt_file_stream,
    decrypt_file_stream,
    CHUNK_SIZE,
)


def test_keypair_generation():
    kp = KeyPair.generate()
    assert kp.private_key is not None
    assert kp.public_key is not None


def test_keypair_serialization():
    kp = KeyPair.generate()
    pub_bytes = kp.serialize_public()
    priv_bytes = kp.serialize_private()

    assert len(pub_bytes) == 32
    assert len(priv_bytes) == 32

    # Round-trip
    kp2 = KeyPair.from_private_bytes(priv_bytes)
    assert kp2.serialize_public() == pub_bytes
    assert kp2.serialize_private() == priv_bytes


def test_keypair_from_public_bytes():
    kp = KeyPair.generate()
    pub_bytes = kp.serialize_public()
    imported = KeyPair.from_public_bytes(pub_bytes)
    assert imported.public_bytes(
        encoding=__import__('cryptography.hazmat.primitives.serialization', fromlist=['serialization']).serialization.Encoding.Raw,
        format=__import__('cryptography.hazmat.primitives.serialization', fromlist=['serialization']).serialization.PublicFormat.Raw,
    ) == pub_bytes


def test_ecdh_key_agreement():
    alice = KeyPair.generate()
    bob = KeyPair.generate()

    alice_shared = derive_shared_key(alice.private_key, bob.public_key)
    bob_shared = derive_shared_key(bob.private_key, alice.public_key)

    assert alice_shared == bob_shared
    assert len(alice_shared) == 32


def test_hkdf_sha256():
    ikm = b"input key material"
    salt = b"salt" * 8  # 32 bytes
    info = b"context info"

    key1 = hkdf_sha256(ikm, salt, info)
    key2 = hkdf_sha256(ikm, salt, info)

    assert key1 == key2
    assert len(key1) == 32

    # Different salt produces different key
    key3 = hkdf_sha256(ikm, b"different" * 4, info)
    assert key1 != key3


def test_chunk_encrypt_decrypt():
    key = b"0" * 32
    plaintext = b"Hello, World! This is a test chunk."

    encrypted = encrypt_chunk(key, plaintext, 0)
    assert len(encrypted) >= 12 + len(plaintext) + 16  # nonce + ciphertext + tag

    decrypted = decrypt_chunk(key, encrypted, 0)
    assert decrypted == plaintext


def test_chunk_index_mismatch():
    key = b"0" * 32
    plaintext = b"test"

    encrypted = encrypt_chunk(key, plaintext, 5)

    # Wrong index should fail
    with pytest.raises(ValueError, match="Chunk index mismatch"):
        decrypt_chunk(key, encrypted, 3)


def test_chunk_tampering():
    key = b"0" * 32
    plaintext = b"test data"

    encrypted = bytearray(encrypt_chunk(key, plaintext, 0))
    # Flip a bit in ciphertext
    encrypted[20] ^= 0x01

    with pytest.raises(Exception):  # AESGCM will raise on tag mismatch
        decrypt_chunk(key, bytes(encrypted), 0)


def test_file_stream_roundtrip():
    key = b"0" * 32
    # Create test data: multiple chunks
    data = b"x" * (CHUNK_SIZE * 3 + 1000)  # 3 full chunks + partial

    chunks = encrypt_file_stream(key, data)
    assert len(chunks) == 4  # 3 full + 1 partial

    decrypted = decrypt_file_stream(key, chunks)
    assert decrypted == data


def test_empty_file():
    key = b"0" * 32
    data = b""

    chunks = encrypt_file_stream(key, data)
    assert len(chunks) == 0

    decrypted = decrypt_file_stream(key, chunks)
    assert decrypted == b""


def test_single_chunk():
    key = b"0" * 32
    data = b"small file"

    chunks = encrypt_file_stream(key, data)
    assert len(chunks) == 1

    decrypted = decrypt_file_stream(key, chunks)
    assert decrypted == data


def test_exact_chunk_boundary():
    key = b"0" * 32
    data = b"x" * CHUNK_SIZE

    chunks = encrypt_file_stream(key, data)
    assert len(chunks) == 1

    decrypted = decrypt_file_stream(key, chunks)
    assert decrypted == data