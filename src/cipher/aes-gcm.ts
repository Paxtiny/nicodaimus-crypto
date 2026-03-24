import { gcm } from '@noble/ciphers/aes.js';
import { randomBytes } from '../utils/random.js';

const NONCE_LENGTH = 12; // 96-bit nonce for AES-GCM

export interface EncryptedBlob {
  nonce: Uint8Array; // 12 bytes
  ciphertext: Uint8Array; // includes 16-byte GCM auth tag
}

/**
 * Encrypt plaintext with AES-256-GCM.
 * Generates a fresh random 12-byte nonce for every call.
 */
export function encrypt(key: Uint8Array, plaintext: Uint8Array): EncryptedBlob {
  const nonce = randomBytes(NONCE_LENGTH);
  const cipher = gcm(key, nonce);
  const ciphertext = cipher.encrypt(plaintext);
  return { nonce, ciphertext };
}

/**
 * Decrypt AES-256-GCM ciphertext.
 * Throws if the auth tag is invalid (tampered data or wrong key).
 */
export function decrypt(key: Uint8Array, blob: EncryptedBlob): Uint8Array {
  const cipher = gcm(key, blob.nonce);
  return cipher.decrypt(blob.ciphertext);
}

/** Serialize EncryptedBlob to a single Uint8Array: nonce || ciphertext. */
export function serialize(blob: EncryptedBlob): Uint8Array {
  const result = new Uint8Array(blob.nonce.length + blob.ciphertext.length);
  result.set(blob.nonce, 0);
  result.set(blob.ciphertext, blob.nonce.length);
  return result;
}

/** Deserialize a Uint8Array back to EncryptedBlob (split at byte 12). */
export function deserialize(data: Uint8Array): EncryptedBlob {
  return {
    nonce: data.slice(0, NONCE_LENGTH),
    ciphertext: data.slice(NONCE_LENGTH),
  };
}
