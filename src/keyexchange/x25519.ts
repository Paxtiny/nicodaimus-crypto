import { x25519 } from '@noble/curves/ed25519.js';

export interface KeyPair {
  publicKey: Uint8Array; // 32 bytes
  secretKey: Uint8Array; // 32 bytes
}

/**
 * Generate an X25519 keypair from a 32-byte seed.
 * If no seed is provided, uses the seed as the secret key directly.
 */
export function generateKeyPair(seed: Uint8Array): KeyPair {
  const publicKey = x25519.getPublicKey(seed);
  return {
    publicKey,
    secretKey: new Uint8Array(seed),
  };
}

/**
 * Compute the X25519 shared secret between my secret key and their public key.
 * Used in the group flow: admin + sub-user derive the same shared secret.
 */
export function getSharedSecret(
  mySecretKey: Uint8Array,
  theirPublicKey: Uint8Array,
): Uint8Array {
  return x25519.getSharedSecret(mySecretKey, theirPublicKey);
}
