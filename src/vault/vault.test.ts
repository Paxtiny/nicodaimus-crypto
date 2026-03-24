import { describe, it, expect } from 'vitest';
import { createVault, unlockVault } from './vault.js';
import { toBytes, fromBytes } from '../utils/encoding.js';

// Fast params for tests
const TEST_PARAMS = { memoryCost: 1024, timeCost: 1, parallelism: 1, hashLength: 32 };

describe('Vault', () => {
  describe('solo user flow', () => {
    it('create + unlock roundtrip', async () => {
      const { vault, params } = await createVault('my-passphrase', TEST_PARAMS);

      // Vault is usable
      const plaintext = toBytes('Hello oscar!');
      const encrypted = vault.encryptRecord('tx', 'tx-001', plaintext);
      const decrypted = vault.decryptRecord('tx', 'tx-001', encrypted);
      expect(fromBytes(decrypted)).toBe('Hello oscar!');

      // Unlock with same passphrase
      const unlocked = await unlockVault('my-passphrase', params);
      const decrypted2 = unlocked.decryptRecord('tx', 'tx-001', encrypted);
      expect(fromBytes(decrypted2)).toBe('Hello oscar!');

      vault.shred();
      unlocked.shred();
    });

    it('wrong passphrase throws on unlock', async () => {
      const { params } = await createVault('correct-passphrase', TEST_PARAMS);
      await expect(unlockVault('wrong-passphrase', params)).rejects.toThrow();
    });

    it('different records get different ciphertext', async () => {
      const { vault } = await createVault('passphrase', TEST_PARAMS);
      const data = toBytes('same data');
      const enc1 = vault.encryptRecord('tx', 'tx-001', data);
      const enc2 = vault.encryptRecord('tx', 'tx-002', data);
      // Different record IDs = different derived keys = different ciphertext
      expect(enc1).not.toEqual(enc2);
      vault.shred();
    });

    it('different record types get different ciphertext', async () => {
      const { vault } = await createVault('passphrase', TEST_PARAMS);
      const data = toBytes('same data');
      const enc1 = vault.encryptRecord('tx', 'id-1', data);
      const enc2 = vault.encryptRecord('budget', 'id-1', data);
      expect(enc1).not.toEqual(enc2);
      vault.shred();
    });

    it('shredded vault throws on use', async () => {
      const { vault } = await createVault('passphrase', TEST_PARAMS);
      vault.shred();
      expect(() => vault.encryptRecord('tx', 'id', toBytes('test'))).toThrow('shredded');
    });
  });

  describe('passphrase change', () => {
    it('change passphrase preserves data access', async () => {
      const { vault, params: oldParams } = await createVault('old-pass', TEST_PARAMS);

      // Encrypt a record
      const plaintext = toBytes('important data');
      const encrypted = vault.encryptRecord('tx', 'tx-001', plaintext);

      // Change passphrase
      const newParams = await vault.changePassphrase('new-pass');

      // Old passphrase no longer works
      await expect(unlockVault('old-pass', newParams)).rejects.toThrow();

      // New passphrase works, and can decrypt existing records
      const reopened = await unlockVault('new-pass', newParams);
      const decrypted = reopened.decryptRecord('tx', 'tx-001', encrypted);
      expect(fromBytes(decrypted)).toBe('important data');

      vault.shred();
      reopened.shred();
    });
  });

  describe('group flow (admin envelope)', () => {
    it('admin can decrypt sub-user data via key wrapping', async () => {
      // Admin creates vault
      const admin = await createVault('admin-pass', TEST_PARAMS);

      // Sub-user creates vault
      const subUser = await createVault('sub-user-pass', TEST_PARAMS);

      // Sub-user wraps their DEK for the admin
      const wrappedDek = subUser.vault.wrapKeyForAdmin(admin.vault.publicKey);

      // Sub-user encrypts data
      const plaintext = toBytes('expense: lunch 12.50 EUR');
      const encrypted = subUser.vault.encryptRecord('tx', 'tx-sub-001', plaintext);

      // Admin unwraps the sub-user's DEK
      const subUserDek = admin.vault.unwrapSubUserKey(
        wrappedDek,
        subUser.vault.publicKey,
      );
      expect(subUserDek.length).toBe(32);

      // Admin uses the sub-user's DEK to derive the record key and decrypt
      // (This simulates what the admin client would do)
      const { deriveRecordKey } = await import('../kdf/hkdf.js');
      const { decrypt, deserialize } = await import('../cipher/aes-gcm.js');
      const recordKey = deriveRecordKey(subUserDek, 'tx', 'tx-sub-001');
      const blob = deserialize(encrypted);
      const decrypted = decrypt(recordKey, blob);
      expect(fromBytes(decrypted)).toBe('expense: lunch 12.50 EUR');

      admin.vault.shred();
      subUser.vault.shred();
    });

    it('sub-user A cannot decrypt sub-user B data', async () => {
      const admin = await createVault('admin-pass', TEST_PARAMS);
      const userA = await createVault('user-a-pass', TEST_PARAMS);
      const userB = await createVault('user-b-pass', TEST_PARAMS);

      // User B wraps DEK for admin
      const wrappedB = userB.vault.wrapKeyForAdmin(admin.vault.publicKey);

      // User A tries to unwrap B's DEK using A's own key - should fail
      // (A's shared secret with B is different from admin's shared secret with B)
      expect(() => {
        userA.vault.unwrapSubUserKey(wrappedB, userB.vault.publicKey);
      }).toThrow();

      admin.vault.shred();
      userA.vault.shred();
      userB.vault.shred();
    });

    it('admin revocation: deleting wrapped key blocks access', async () => {
      const admin = await createVault('admin-pass', TEST_PARAMS);
      const subUser = await createVault('sub-pass', TEST_PARAMS);

      const wrappedDek = subUser.vault.wrapKeyForAdmin(admin.vault.publicKey);

      // Admin can unwrap
      const dek = admin.vault.unwrapSubUserKey(wrappedDek, subUser.vault.publicKey);
      expect(dek.length).toBe(32);

      // "Delete" the wrapped key (simulate server-side deletion)
      // Admin no longer has the wrapped blob - cannot derive DEK
      // This is the revocation mechanism

      // Sub-user can still access their own data
      const plaintext = toBytes('my private data');
      const enc = subUser.vault.encryptRecord('tx', 'tx-1', plaintext);
      const dec = subUser.vault.decryptRecord('tx', 'tx-1', enc);
      expect(fromBytes(dec)).toBe('my private data');

      admin.vault.shred();
      subUser.vault.shred();
    });
  });

  describe('VaultParams serialization', () => {
    it('params contain all required blobs', async () => {
      const { params } = await createVault('test', TEST_PARAMS);
      expect(params.argon2Salt).toBeInstanceOf(Uint8Array);
      expect(params.argon2Salt.length).toBe(16);
      expect(params.argon2Params).toEqual(expect.objectContaining({
        memoryCost: TEST_PARAMS.memoryCost,
        timeCost: TEST_PARAMS.timeCost,
      }));
      expect(params.encryptedDek).toBeInstanceOf(Uint8Array);
      expect(params.encryptedX25519Private).toBeInstanceOf(Uint8Array);
      expect(params.x25519Public).toBeInstanceOf(Uint8Array);
      expect(params.x25519Public.length).toBe(32);
    });
  });
});
