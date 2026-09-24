/**
 * Crypto module for SecureDrop-Lite frontend.
 * Implements X25519 (ECDH) + AES-GCM (HKDF-SHA256) using Web Crypto API.
 */

const CHUNK_SIZE = 64 * 1024; // 64 KiB
const NONCE_SIZE = 12;
const TAG_SIZE = 16;
const SALT_SIZE = 32;
const KEY_SIZE = 32;

/**
 * Generate X25519 key pair.
 * @returns {Promise<{privateKey: CryptoKey, publicKey: CryptoKey}>}
 */
export async function generateKeyPair() {
  return await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'X25519' },
    true,
    ['deriveBits', 'deriveKey']
  );
}

/**
 * Export public key as raw bytes.
 * @param {CryptoKey} publicKey
 * @returns {Promise<Uint8Array>}
 */
export async function exportPublicKey(publicKey) {
  const raw = await crypto.subtle.exportKey('raw', publicKey);
  return new Uint8Array(raw);
}

/**
 * Import public key from raw bytes.
 * @param {Uint8Array} raw
 * @returns {Promise<CryptoKey>}
 */
export async function importPublicKey(raw) {
  return await crypto.subtle.importKey(
    'raw', raw,
    { name: 'ECDH', namedCurve: 'X25519' },
    true,
    []
  );
}

/**
 * Derive shared secret using X25519 ECDH.
 * @param {CryptoKey} privateKey
 * @param {CryptoKey} peerPublicKey
 * @returns {Promise<Uint8Array>}
 */
export async function deriveSharedSecret(privateKey, peerPublicKey) {
  const sharedBits = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: peerPublicKey },
    privateKey,
    256
  );
  return new Uint8Array(sharedBits);
}

/**
 * HKDF-SHA256 key derivation.
 * @param {Uint8Array} ikm - Input key material
 * @param {Uint8Array} salt - Salt (32 bytes)
 * @param {Uint8Array} info - Context info
 * @param {number} length - Output length in bytes
 * @returns {Promise<Uint8Array>}
 */
export async function hkdfSha256(ikm, salt, info, length = KEY_SIZE) {
  const baseKey = await crypto.subtle.importKey(
    'raw', ikm,
    { name: 'HKDF' },
    false,
    ['deriveBits']
  );
  const derived = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt,
      info
    },
    baseKey,
    length * 8
  );
  return new Uint8Array(derived);
}

/**
 * Encrypt a chunk with AES-GCM.
 * @param {CryptoKey} key - AES-GCM key
 * @param {Uint8Array} plaintext - Data to encrypt
 * @param {number} chunkIndex - Chunk index for nonce uniqueness
 * @returns {Promise<Uint8Array>} nonce + ciphertext
 */
export async function encryptChunk(key, plaintext, chunkIndex) {
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_SIZE));
  // Embed chunk index in first 4 bytes of nonce
  const indexBytes = new Uint8Array([
    (chunkIndex >>> 24) & 0xff,
    (chunkIndex >>> 16) & 0xff,
    (chunkIndex >>> 8) & 0xff,
    chunkIndex & 0xff
  ]);
  nonce.set(indexBytes, 0);

  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, tagLength: 128 },
    key,
    plaintext
  );

  const result = new Uint8Array(NONCE_SIZE + ciphertext.byteLength);
  result.set(nonce, 0);
  result.set(new Uint8Array(ciphertext), NONCE_SIZE);
  return result;
}

/**
 * Decrypt a chunk with AES-GCM.
 * @param {CryptoKey} key - AES-GCM key
 * @param {Uint8Array} data - nonce + ciphertext
 * @param {number} chunkIndex - Expected chunk index
 * @returns {Promise<Uint8Array>} Decrypted plaintext
 */
export async function decryptChunk(key, data, chunkIndex) {
  if (data.length < NONCE_SIZE + TAG_SIZE) {
    throw new Error('Invalid chunk data');
  }

  const nonce = data.slice(0, NONCE_SIZE);
  const expectedPrefix = new Uint8Array([
    (chunkIndex >>> 24) & 0xff,
    (chunkIndex >>> 16) & 0xff,
    (chunkIndex >>> 8) & 0xff,
    chunkIndex & 0xff
  ]);

  // Verify chunk index matches
  for (let i = 0; i < 4; i++) {
    if (nonce[i] !== expectedPrefix[i]) {
      throw new Error('Chunk index mismatch');
    }
  }

  const ciphertext = data.slice(NONCE_SIZE);
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonce, tagLength: 128 },
    key,
    ciphertext
  );
  return new Uint8Array(plaintext);
}

/**
 * Encrypt file data in chunks.
 * @param {CryptoKey} key - AES-GCM key
 * @param {Uint8Array} fileData - File data to encrypt
 * @returns {Promise<Uint8Array[]>} Array of encrypted chunks
 */
export async function encryptFile(key, fileData) {
  const chunks = [];
  for (let i = 0; i < fileData.length; i += CHUNK_SIZE) {
    const chunk = fileData.slice(i, i + CHUNK_SIZE);
    const chunkIndex = Math.floor(i / CHUNK_SIZE);
    const encrypted = await encryptChunk(key, chunk, chunkIndex);
    chunks.push(encrypted);
  }
  return chunks;
}

/**
 * Decrypt file from chunks.
 * @param {CryptoKey} key - AES-GCM key
 * @param {Uint8Array[]} chunks - Encrypted chunks
 * @returns {Promise<Uint8Array>} Decrypted file data
 */
export async function decryptFile(key, chunks) {
  const parts = [];
  let totalLength = 0;
  for (let i = 0; i < chunks.length; i++) {
    const decrypted = await decryptChunk(key, chunks[i], i);
    parts.push(decrypted);
    totalLength += decrypted.length;
  }
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

/**
 * Create AES-GCM key from raw bytes.
 * @param {Uint8Array} rawKey - 32-byte key
 * @returns {Promise<CryptoKey>}
 */
export async function createAesGcmKey(rawKey) {
  return await crypto.subtle.importKey(
    'raw', rawKey,
    { name: 'AES-GCM' },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Generate random salt.
 * @returns {Uint8Array}
 */
export function generateSalt() {
  return crypto.getRandomValues(new Uint8Array(SALT_SIZE));
}

/**
 * Generate session ID.
 * @returns {string}
 */
export function generateSessionId() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Format bytes as human-readable string.
 * @param {number} bytes
 * @returns {string}
 */
export function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KiB', 'MiB', 'GiB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

/**
 * Format speed as human-readable string.
 * @param {number} bytesPerSecond
 * @returns {string}
 */
export function formatSpeed(bytesPerSecond) {
  return formatBytes(bytesPerSecond) + '/s';
}