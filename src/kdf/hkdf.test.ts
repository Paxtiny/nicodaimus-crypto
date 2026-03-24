import { describe, it, expect } from 'vitest';
import { deriveSubkey, deriveRecordKey } from './hkdf.js';

describe('HKDF-SHA256', () => {
  const ikm = new Uint8Array(32).fill(0xab);

  it('produces 32-byte key by default', () => {
    const key = deriveSubkey(ikm, 'test-context');
    expect(key.length).toBe(32);
  });

  it('produces custom-length key', () => {
    const key = deriveSubkey(ikm, 'test-context', 64);
    expect(key.length).toBe(64);
  });

  it('same inputs produce same output (deterministic)', () => {
    const k1 = deriveSubkey(ikm, 'test-context');
    const k2 = deriveSubkey(ikm, 'test-context');
    expect(k1).toEqual(k2);
  });

  it('different context produces different key', () => {
    const k1 = deriveSubkey(ikm, 'context-a');
    const k2 = deriveSubkey(ikm, 'context-b');
    expect(k1).not.toEqual(k2);
  });

  it('different IKM produces different key', () => {
    const ikm2 = new Uint8Array(32).fill(0xcd);
    const k1 = deriveSubkey(ikm, 'test');
    const k2 = deriveSubkey(ikm2, 'test');
    expect(k1).not.toEqual(k2);
  });

  it('deriveRecordKey produces unique keys per record', () => {
    const dek = new Uint8Array(32).fill(0x01);
    const k1 = deriveRecordKey(dek, 'tx', 'id-1');
    const k2 = deriveRecordKey(dek, 'tx', 'id-2');
    const k3 = deriveRecordKey(dek, 'budget', 'id-1');
    expect(k1).not.toEqual(k2);
    expect(k1).not.toEqual(k3);
  });

  it('output is non-zero and deterministic across calls', () => {
    const key = deriveSubkey(ikm, 'oscar-dek-v1');
    expect(key).toBeInstanceOf(Uint8Array);
    expect(key.length).toBe(32);
    expect(key.some(b => b !== 0)).toBe(true);
    // Same call again must match
    expect(deriveSubkey(ikm, 'oscar-dek-v1')).toEqual(key);
  });
});
