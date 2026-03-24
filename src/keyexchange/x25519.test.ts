import { describe, it, expect } from 'vitest';
import { generateKeyPair, getSharedSecret } from './x25519.js';
import { randomBytes } from '../utils/random.js';

describe('X25519', () => {
  it('generates a keypair from seed', () => {
    const seed = randomBytes(32);
    const kp = generateKeyPair(seed);
    expect(kp.publicKey.length).toBe(32);
    expect(kp.secretKey.length).toBe(32);
  });

  it('same seed = same keypair (deterministic)', () => {
    const seed = randomBytes(32);
    const kp1 = generateKeyPair(new Uint8Array(seed));
    const kp2 = generateKeyPair(new Uint8Array(seed));
    expect(kp1.publicKey).toEqual(kp2.publicKey);
    expect(kp1.secretKey).toEqual(kp2.secretKey);
  });

  it('different seeds = different keypairs', () => {
    const kp1 = generateKeyPair(randomBytes(32));
    const kp2 = generateKeyPair(randomBytes(32));
    expect(kp1.publicKey).not.toEqual(kp2.publicKey);
  });

  it('Diffie-Hellman: both sides compute same shared secret', () => {
    const alice = generateKeyPair(randomBytes(32));
    const bob = generateKeyPair(randomBytes(32));
    const sharedAlice = getSharedSecret(alice.secretKey, bob.publicKey);
    const sharedBob = getSharedSecret(bob.secretKey, alice.publicKey);
    expect(sharedAlice).toEqual(sharedBob);
    expect(sharedAlice.length).toBe(32);
  });

  it('different key pairs = different shared secrets', () => {
    const alice = generateKeyPair(randomBytes(32));
    const bob = generateKeyPair(randomBytes(32));
    const carol = generateKeyPair(randomBytes(32));
    const sharedAB = getSharedSecret(alice.secretKey, bob.publicKey);
    const sharedAC = getSharedSecret(alice.secretKey, carol.publicKey);
    expect(sharedAB).not.toEqual(sharedAC);
  });
});
