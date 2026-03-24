import { describe, it, expect } from 'vitest';
import { boxEncrypt, boxDecrypt } from './nacl-box.js';
import { randomBytes } from '../utils/random.js';

describe('XSalsa20-Poly1305 (NaCl box)', () => {
  const sharedSecret = randomBytes(32);
  const plaintext = new Uint8Array([1, 2, 3, 4, 5]);

  it('encrypt/decrypt roundtrip', () => {
    const ciphertext = boxEncrypt(sharedSecret, plaintext);
    const result = boxDecrypt(sharedSecret, ciphertext);
    expect(result).toEqual(plaintext);
  });

  it('ciphertext includes 24-byte nonce + 16-byte tag', () => {
    const ciphertext = boxEncrypt(sharedSecret, plaintext);
    // managedNonce prepends 24-byte nonce, poly1305 adds 16-byte tag
    expect(ciphertext.length).toBe(24 + plaintext.length + 16);
  });

  it('wrong key throws', () => {
    const ciphertext = boxEncrypt(sharedSecret, plaintext);
    const wrongKey = randomBytes(32);
    expect(() => boxDecrypt(wrongKey, ciphertext)).toThrow();
  });

  it('tampered ciphertext throws', () => {
    const ciphertext = boxEncrypt(sharedSecret, plaintext);
    ciphertext[ciphertext.length - 1] ^= 0xff;
    expect(() => boxDecrypt(sharedSecret, ciphertext)).toThrow();
  });

  it('different encryptions produce different ciphertext (unique nonce)', () => {
    const ct1 = boxEncrypt(sharedSecret, plaintext);
    const ct2 = boxEncrypt(sharedSecret, plaintext);
    expect(ct1).not.toEqual(ct2);
  });
});
