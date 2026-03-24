# @nicodaimus/crypto

Shared encryption library for [nicodAImus](https://nicodaimus.com) projects (oscar, chat platform).

User-passphrase-derived, operator-inaccessible encryption. Built entirely on audited, zero-dependency [@noble](https://paulmillr.com/noble/) cryptographic primitives.

## Primitives

| Purpose | Algorithm | Module |
|---------|-----------|--------|
| Passphrase to master key | Argon2id | `kdf/argon2` |
| Per-record key derivation | HKDF-SHA256 | `kdf/hkdf` |
| Data encryption | AES-256-GCM | `cipher/aes-gcm` |
| Key wrapping (groups) | XSalsa20-Poly1305 | `cipher/nacl-box` |
| Key agreement (groups) | X25519 | `keyexchange/x25519` |

## Install

```bash
npm install @nicodaimus/crypto
```

## Quick start

### Solo user - create a vault

```typescript
import { createVault, unlockVault, toBytes, fromBytes } from '@nicodaimus/crypto';

// Onboarding: user picks a passphrase
const { vault, params } = await createVault('user-passphrase');
// Send `params` to the server (all encrypted blobs, no secrets)

// Encrypt a record
const ciphertext = vault.encryptRecord('tx', 'tx-001', toBytes(JSON.stringify({
  amount: 12.50,
  vendor: 'Coffee Shop',
  category: 'dining',
})));

// Decrypt
const plaintext = JSON.parse(fromBytes(vault.decryptRecord('tx', 'tx-001', ciphertext)));

// Done for the session
vault.shred();
```

### Returning user - unlock

```typescript
// Fetch params from server, then unlock with passphrase
const vault = await unlockVault('user-passphrase', paramsFromServer);
// Wrong passphrase throws (AES-GCM auth tag mismatch)
```

### Change passphrase

```typescript
const newParams = await vault.changePassphrase('new-passphrase');
// Send newParams to server. O(1) operation - data is NOT re-encrypted.
// The DEK stays the same, only its wrapping changes.
```

### Group flow - admin envelope encryption

```typescript
import { createVault } from '@nicodaimus/crypto';

// Admin and sub-user each have their own vault
const admin = await createVault('admin-pass');
const subUser = await createVault('sub-user-pass');

// Sub-user wraps their DEK for the admin's public key
const wrappedDek = subUser.vault.wrapKeyForAdmin(admin.vault.publicKey);
// Store wrappedDek + subUser.vault.publicKey on the server

// Admin unwraps to read sub-user data
const subUserDek = admin.vault.unwrapSubUserKey(wrappedDek, subUser.vault.publicKey);

// Admin revocation: delete wrappedDek from server = access revoked
// Sub-user still has access to their own data via their passphrase
```

### Low-level primitives

```typescript
import { deriveKey, generateSalt } from '@nicodaimus/crypto/kdf';
import { encrypt, decrypt } from '@nicodaimus/crypto/cipher';

// Argon2id key derivation
const salt = generateSalt();
const key = await deriveKey('passphrase', salt, {
  memoryCost: 65536, // 64 MiB
  timeCost: 3,
  parallelism: 1,
  hashLength: 32,
});

// AES-256-GCM
const blob = encrypt(key, plaintext);
const result = decrypt(key, blob);
```

## Key hierarchy

```
User passphrase (never leaves client)
    |
    v
[Argon2id] + salt -----> Master Key (256-bit, in-memory only)
    |
    +---> [HKDF] "oscar-dek-v1"     ---> DEK (Data Encryption Key)
    |         |
    |         +---> [HKDF] "tx:id"   ---> Per-Record Key ---> [AES-256-GCM]
    |
    +---> [HKDF] "oscar-x25519-v1"  ---> X25519 Keypair (for groups)
```

## Security properties

- **Operator-inaccessible:** Server stores only encrypted blobs. Cannot derive keys without the passphrase.
- **Per-record keys:** Each record gets a unique key via HKDF. Compromising one record key does not affect others.
- **Crypto-shredding:** Delete the Argon2 salt and all data becomes permanently unreadable.
- **Passphrase change is O(1):** Only the key-wrapping blobs change, not every record.
- **Group isolation:** Sub-users are cryptographically isolated from each other. Only the admin can decrypt sub-user data via X25519 key agreement.
- **No custom crypto:** All primitives from [@noble/ciphers](https://github.com/paulmillr/noble-ciphers), [@noble/hashes](https://github.com/paulmillr/noble-hashes), [@noble/curves](https://github.com/paulmillr/noble-curves).

## Testing

```bash
npm test            # run all tests (55 tests)
npm run test:watch  # watch mode
npm run build       # type-check + emit dist/
```

## Argon2id benchmarking

```bash
npm run benchmark   # test derivation time on this machine
```

Target: 500ms-1s derivation time. Adjust `memoryCost` and `timeCost` for your target devices.

## License

MIT
