import { randomBytes as nobleRandomBytes } from '@noble/ciphers/utils.js';

/** Generate cryptographically secure random bytes. */
export function randomBytes(length: number): Uint8Array {
  return nobleRandomBytes(length);
}
