"""Cryptography utilities for SecureDrop-Lite.

Implements X25519 (ECDH) key agreement + AES-GCM (HKDF-SHA256) encryption.
"""

import os
from dataclasses import dataclass
from typing import ClassVar

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


CHUNK_SIZE = 64 * 1024  # 64 KiB
NONCE_SIZE = 12
TAG_SIZE = 16
SALT_SIZE = 32
KEY_SIZE = 32


@dataclass
class KeyPair:
    """X25519 key pair."""
    private_key: X25519PrivateKey
    public_key: X25519PublicKey

    @classmethod
    def generate(cls) -> "KeyPair":
        private = X25519PrivateKey.generate()
        return cls(private_key=private, public_key=private.public_key())

    def serialize_public(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def serialize_private(self) -> bytes:
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

    @classmethod
    def from_private_bytes(cls, data: bytes) -> "KeyPair":
        private = X25519PrivateKey.from_private_bytes(data)
        return cls(private_key=private, public_key=private.public_key())

    @classmethod
    def from_public_bytes(cls, data: bytes) -> X25519PublicKey:
        return X25519PublicKey.from_public_bytes(data)


def derive_shared_key(private_key: X25519PrivateKey, peer_public_key: X25519PublicKey) -> bytes:
    """Derive shared secret using X25519 ECDH."""
    return private_key.exchange(peer_public_key)


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = KEY_SIZE) -> bytes:
    """HKDF-SHA256 key derivation."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(ikm)


def encrypt_chunk(key: bytes, plaintext: bytes, chunk_index: int) -> bytes:
    """Encrypt a chunk with AES-GCM. Returns nonce + ciphertext + tag."""
    nonce = os.urandom(NONCE_SIZE)
    # Include chunk index in nonce to prevent replay
    nonce_with_index = bytes([chunk_index >> 24 & 0xFF, chunk_index >> 16 & 0xFF,
                               chunk_index >> 8 & 0xFF, chunk_index & 0xFF]) + nonce[4:]
    aead = AESGCM(key)
    ciphertext = aead.encrypt(nonce_with_index, plaintext, None)
    return nonce_with_index + ciphertext


def decrypt_chunk(key: bytes, data: bytes, chunk_index: int) -> bytes:
    """Decrypt a chunk with AES-GCM. Expects nonce + ciphertext + tag."""
    if len(data) < NONCE_SIZE + TAG_SIZE:
        raise ValueError("Invalid chunk data")
    nonce = data[:NONCE_SIZE]
    # Verify chunk index matches
    expected_prefix = bytes([chunk_index >> 24 & 0xFF, chunk_index >> 16 & 0xFF,
                              chunk_index >> 8 & 0xFF, chunk_index & 0xFF])
    if nonce[:4] != expected_prefix:
        raise ValueError("Chunk index mismatch")
    ciphertext = data[NONCE_SIZE:]
    aead = AESGCM(key)
    return aead.decrypt(nonce, ciphertext, None)


def encrypt_file_stream(key: bytes, file_data: bytes) -> list[bytes]:
    """Encrypt file data in 64 KiB chunks. Returns list of encrypted chunks."""
    chunks = []
    for i in range(0, len(file_data), CHUNK_SIZE):
        chunk = file_data[i:i + CHUNK_SIZE]
        chunk_index = i // CHUNK_SIZE
        encrypted = encrypt_chunk(key, chunk, chunk_index)
        chunks.append(encrypted)
    return chunks


def decrypt_file_stream(key: bytes, chunks: list[bytes]) -> bytes:
    """Decrypt file from encrypted chunks."""
    plaintext = bytearray()
    for i, chunk in enumerate(chunks):
        decrypted = decrypt_chunk(key, chunk, i)
        plaintext.extend(decrypted)
    return bytes(plaintext)