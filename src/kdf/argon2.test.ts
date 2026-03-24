import { describe, it, expect } from 'vitest';
import { deriveKey, generateSalt, DEFAULT_ARGON2_PARAMS } from './argon2.js';

// Use fast params for tests (64 MiB is too slow for CI)
const TEST_PARAMS = { memoryCost: 1024, timeCost: 1, parallelism: 1, hashLength: 32 };

describe('Argon2id', () => {
  it('generateSalt returns 16 bytes', () => {
    const salt = generateSalt();
    expect(salt.length).toBe(16);
  });

  it('generateSalt returns unique values', () => {
    const s1 = generateSalt();
    const s2 = generateSalt();
    expect(s1).not.toEqual(s2);
  });

  it('derives a 32-byte key', async () => {
    const salt = generateSalt();
    const key = await deriveKey('test-passphrase', salt, TEST_PARAMS);
    expect(key.length).toBe(32);
    expect(key).toBeInstanceOf(Uint8Array);
  });

  it('same passphrase + salt = same key (deterministic)', async () => {
    const salt = generateSalt();
    const k1 = await deriveKey('my-passphrase', salt, TEST_PARAMS);
    const k2 = await deriveKey('my-passphrase', salt, TEST_PARAMS);
    expect(k1).toEqual(k2);
  });

  it('different passphrase = different key', async () => {
    const salt = generateSalt();
    const k1 = await deriveKey('passphrase-1', salt, TEST_PARAMS);
    const k2 = await deriveKey('passphrase-2', salt, TEST_PARAMS);
    expect(k1).not.toEqual(k2);
  });

  it('different salt = different key', async () => {
    const s1 = generateSalt();
    const s2 = generateSalt();
    const k1 = await deriveKey('same-passphrase', s1, TEST_PARAMS);
    const k2 = await deriveKey('same-passphrase', s2, TEST_PARAMS);
    expect(k1).not.toEqual(k2);
  });

  it('supports custom hash length', async () => {
    const salt = generateSalt();
    const key = await deriveKey('test', salt, { ...TEST_PARAMS, hashLength: 64 });
    expect(key.length).toBe(64);
  });

  it('default params match spec', () => {
    expect(DEFAULT_ARGON2_PARAMS.memoryCost).toBe(65536); // 64 MiB
    expect(DEFAULT_ARGON2_PARAMS.timeCost).toBe(3);
    expect(DEFAULT_ARGON2_PARAMS.parallelism).toBe(1);
    expect(DEFAULT_ARGON2_PARAMS.hashLength).toBe(32);
  });
});
