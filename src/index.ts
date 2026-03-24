// KDF
export { deriveKey, generateSalt, DEFAULT_ARGON2_PARAMS } from './kdf/argon2.js';
export type { Argon2Params } from './kdf/argon2.js';
export { deriveSubkey, deriveRecordKey } from './kdf/hkdf.js';

// Ciphers
export { encrypt, decrypt, serialize, deserialize } from './cipher/aes-gcm.js';
export type { EncryptedBlob } from './cipher/aes-gcm.js';
export { boxEncrypt, boxDecrypt } from './cipher/nacl-box.js';

// Key exchange
export { generateKeyPair, getSharedSecret } from './keyexchange/x25519.js';
export type { KeyPair } from './keyexchange/x25519.js';

// Vault (high-level API)
export { createVault, unlockVault } from './vault/vault.js';
export type { Vault, VaultParams } from './vault/types.js';

// Utilities
export { randomBytes } from './utils/random.js';
export { toBytes, fromBytes, toHex, fromHex, toBase64, fromBase64 } from './utils/encoding.js';
export { shred, shredAll } from './utils/shred.js';
