import { describe, it, expect } from 'vitest';
import { encrypt, decrypt, serialize, deserialize } from './aes-gcm.js';
import { randomBytes } from '../utils/random.js';

describe('AES-256-GCM', () => {
  const key = randomBytes(32);
  const plaintext = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"

  it('encrypt/decrypt roundtrip', () => {
    const blob = encrypt(key, plaintext);
    const result = decrypt(key, blob);
    expect(result).toEqual(plaintext);
  });

  it('produces different nonces each call', () => {
    const blob1 = encrypt(key, plaintext);
    const blob2 = encrypt(key, plaintext);
    expect(blob1.nonce).not.toEqual(blob2.nonce);
  });

  it('nonce is 12 bytes', () => {
    const blob = encrypt(key, plaintext);
    expect(blob.nonce.length).toBe(12);
  });

  it('ciphertext includes 16-byte auth tag', () => {
    const blob = encrypt(key, plaintext);
    // ciphertext = plaintext + 16 byte tag
    expect(blob.ciphertext.length).toBe(plaintext.length + 16);
  });

  it('wrong key throws', () => {
    const blob = encrypt(key, plaintext);
    const wrongKey = randomBytes(32);
    expect(() => decrypt(wrongKey, blob)).toThrow();
  });

  it('tampered ciphertext throws', () => {
    const blob = encrypt(key, plaintext);
    blob.ciphertext[0] ^= 0xff; // flip a byte
    expect(() => decrypt(key, blob)).toThrow();
  });

  it('tampered nonce throws', () => {
    const blob = encrypt(key, plaintext);
    blob.nonce[0] ^= 0xff;
    expect(() => decrypt(key, blob)).toThrow();
  });

  it('serialize/deserialize roundtrip', () => {
    const blob = encrypt(key, plaintext);
    const serialized = serialize(blob);
    const deserialized = deserialize(serialized);
    expect(deserialized.nonce).toEqual(blob.nonce);
    expect(deserialized.ciphertext).toEqual(blob.ciphertext);
    // And decryption still works
    expect(decrypt(key, deserialized)).toEqual(plaintext);
  });

  it('serialized format is nonce||ciphertext', () => {
    const blob = encrypt(key, plaintext);
    const serialized = serialize(blob);
    expect(serialized.length).toBe(12 + plaintext.length + 16);
    expect(serialized.slice(0, 12)).toEqual(blob.nonce);
    expect(serialized.slice(12)).toEqual(blob.ciphertext);
  });

  it('handles empty plaintext', () => {
    const empty = new Uint8Array(0);
    const blob = encrypt(key, empty);
    expect(decrypt(key, blob)).toEqual(empty);
  });

  it('handles large plaintext', () => {
    const large = randomBytes(1024 * 64); // 64 KiB
    const blob = encrypt(key, large);
    expect(decrypt(key, blob)).toEqual(large);
  });
});
