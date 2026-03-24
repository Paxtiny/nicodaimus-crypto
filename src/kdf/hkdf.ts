import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { toBytes } from '../utils/encoding.js';

/**
 * Derive a subkey from input key material using HKDF-SHA256.
 * @param ikm - Input key material (e.g., master key or DEK)
 * @param info - Context string (e.g., "oscar-dek-v1")
 * @param length - Output key length in bytes (default: 32)
 */
export function deriveSubkey(
  ikm: Uint8Array,
  info: string,
  length: number = 32,
): Uint8Array {
  return hkdf(sha256, ikm, undefined, toBytes(info), length);
}

/**
 * Derive a per-record encryption key.
 * Uses HKDF(DEK, "recordType:recordId") to produce a unique key per record.
 */
export function deriveRecordKey(
  dek: Uint8Array,
  recordType: string,
  recordId: string,
): Uint8Array {
  return deriveSubkey(dek, `${recordType}:${recordId}`);
}
