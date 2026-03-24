import { randomBytes } from '../utils/random.js';

export interface Argon2Params {
  memoryCost: number; // KiB (default: 65536 = 64 MiB)
  timeCost: number; // iterations (default: 3)
  parallelism: number; // threads (default: 1)
  hashLength: number; // output bytes (default: 32)
}

export const DEFAULT_ARGON2_PARAMS: Argon2Params = {
  memoryCost: 65536,
  timeCost: 3,
  parallelism: 1,
  hashLength: 32,
};

/** Generate a random 16-byte salt for Argon2id. */
export function generateSalt(): Uint8Array {
  return randomBytes(16);
}

/**
 * Derive a key from a passphrase using Argon2id.
 *
 * Environment-adaptive:
 * - Node.js: uses native `argon2` package (C++ binding, fast)
 * - Fallback: uses @noble/hashes argon2id (pure JS, slower but works everywhere)
 */
export async function deriveKey(
  passphrase: string,
  salt: Uint8Array,
  params?: Partial<Argon2Params>,
): Promise<Uint8Array> {
  const p: Argon2Params = { ...DEFAULT_ARGON2_PARAMS, ...params };

  // Try native argon2 package first (Node.js only, optional dependency)
  try {
    const argon2 = await import('argon2');
    const result = await argon2.hash(passphrase, {
      type: argon2.argon2id,
      salt: Buffer.from(salt),
      memoryCost: p.memoryCost,
      timeCost: p.timeCost,
      parallelism: p.parallelism,
      hashLength: p.hashLength,
      raw: true,
    });
    return new Uint8Array(result);
  } catch {
    // Native argon2 not available, fall back to @noble/hashes
  }

  // Fallback: pure JS implementation from @noble/hashes
  const { argon2id } = await import('@noble/hashes/argon2.js');
  const encoder = new TextEncoder();
  return argon2id(encoder.encode(passphrase), salt, {
    m: p.memoryCost,
    t: p.timeCost,
    p: p.parallelism,
    dkLen: p.hashLength,
  });
}
