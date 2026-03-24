import { xsalsa20poly1305 } from '@noble/ciphers/salsa.js';
import { managedNonce } from '@noble/ciphers/utils.js';

/**
 * XSalsa20-Poly1305 encryption with auto-managed 24-byte nonce.
 * Used for key wrapping in the group flow (admin envelope model).
 *
 * The nonce is prepended to the ciphertext automatically by managedNonce.
 */

const createCipher = managedNonce(xsalsa20poly1305);

/** Encrypt plaintext with a shared secret (from X25519 DH). */
export function boxEncrypt(
  sharedSecret: Uint8Array,
  plaintext: Uint8Array,
): Uint8Array {
  const cipher = createCipher(sharedSecret);
  return cipher.encrypt(plaintext);
}

/**
 * Decrypt ciphertext with a shared secret.
 * Throws if the Poly1305 auth tag is invalid.
 */
export function boxDecrypt(
  sharedSecret: Uint8Array,
  ciphertext: Uint8Array,
): Uint8Array {
  const cipher = createCipher(sharedSecret);
  return cipher.decrypt(ciphertext);
}
