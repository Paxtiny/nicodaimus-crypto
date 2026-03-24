import type { Argon2Params } from '../kdf/argon2.js';

/** Stored server-side. Server can't derive keys without the passphrase. */
export interface VaultParams {
  argon2Salt: Uint8Array;
  argon2Params: Argon2Params;
  encryptedDek: Uint8Array; // DEK encrypted with masterKey (AES-GCM: nonce || ciphertext)
  encryptedX25519Private: Uint8Array; // X25519 private key encrypted with masterKey
  x25519Public: Uint8Array; // 32 bytes, plaintext (stored server-side)
}

/** An unlocked vault that can encrypt/decrypt records. */
export interface Vault {
  readonly params: VaultParams;
  readonly publicKey: Uint8Array;

  /** Encrypt a record (e.g., transaction). Returns serialized nonce || ciphertext. */
  encryptRecord(
    recordType: string,
    recordId: string,
    plaintext: Uint8Array,
  ): Uint8Array;

  /** Decrypt a record. Throws on tamper or wrong key. */
  decryptRecord(
    recordType: string,
    recordId: string,
    ciphertext: Uint8Array,
  ): Uint8Array;

  /** Wrap this vault's DEK for an admin (sub-user -> admin key exchange). */
  wrapKeyForAdmin(adminPublicKey: Uint8Array): Uint8Array;

  /** Unwrap a sub-user's DEK (admin only). Returns the sub-user's DEK. */
  unwrapSubUserKey(
    wrappedDek: Uint8Array,
    subUserPublicKey: Uint8Array,
  ): Uint8Array;

  /** Change passphrase. Returns new VaultParams (DEK stays the same). */
  changePassphrase(newPassphrase: string): Promise<VaultParams>;

  /** Zero all in-memory keys. Subsequent operations will throw. */
  shred(): void;
}
