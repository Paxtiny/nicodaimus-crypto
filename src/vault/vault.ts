import type { Argon2Params } from '../kdf/argon2.js';
import type { Vault, VaultParams } from './types.js';
import { deriveKey, generateSalt, DEFAULT_ARGON2_PARAMS } from '../kdf/argon2.js';
import { deriveSubkey, deriveRecordKey } from '../kdf/hkdf.js';
import * as aesGcm from '../cipher/aes-gcm.js';
import { boxEncrypt, boxDecrypt } from '../cipher/nacl-box.js';
import { generateKeyPair, getSharedSecret } from '../keyexchange/x25519.js';
import { shredAll } from '../utils/shred.js';

// HKDF context strings (versioned for future-proofing)
const DEK_CONTEXT = 'oscar-dek-v1';
const X25519_CONTEXT = 'oscar-x25519-v1';

class VaultImpl implements Vault {
  private _dek: Uint8Array;
  private _x25519Secret: Uint8Array;
  private _params: VaultParams;
  private _shredded = false;

  constructor(
    dek: Uint8Array,
    x25519Secret: Uint8Array,
    params: VaultParams,
  ) {
    this._dek = dek;
    this._x25519Secret = x25519Secret;
    this._params = params;
  }

  get params(): VaultParams {
    return this._params;
  }

  get publicKey(): Uint8Array {
    return this._params.x25519Public;
  }

  private assertNotShredded(): void {
    if (this._shredded) {
      throw new Error('Vault has been shredded');
    }
  }

  encryptRecord(
    recordType: string,
    recordId: string,
    plaintext: Uint8Array,
  ): Uint8Array {
    this.assertNotShredded();
    const recordKey = deriveRecordKey(this._dek, recordType, recordId);
    const blob = aesGcm.encrypt(recordKey, plaintext);
    shredAll(recordKey);
    return aesGcm.serialize(blob);
  }

  decryptRecord(
    recordType: string,
    recordId: string,
    ciphertext: Uint8Array,
  ): Uint8Array {
    this.assertNotShredded();
    const recordKey = deriveRecordKey(this._dek, recordType, recordId);
    const blob = aesGcm.deserialize(ciphertext);
    const plaintext = aesGcm.decrypt(recordKey, blob);
    shredAll(recordKey);
    return plaintext;
  }

  wrapKeyForAdmin(adminPublicKey: Uint8Array): Uint8Array {
    this.assertNotShredded();
    const shared = getSharedSecret(this._x25519Secret, adminPublicKey);
    const wrapped = boxEncrypt(shared, this._dek);
    shredAll(shared);
    return wrapped;
  }

  unwrapSubUserKey(
    wrappedDek: Uint8Array,
    subUserPublicKey: Uint8Array,
  ): Uint8Array {
    this.assertNotShredded();
    const shared = getSharedSecret(this._x25519Secret, subUserPublicKey);
    const dek = boxDecrypt(shared, wrappedDek);
    shredAll(shared);
    return dek;
  }

  async changePassphrase(newPassphrase: string): Promise<VaultParams> {
    this.assertNotShredded();
    const newSalt = generateSalt();
    const newMasterKey = await deriveKey(
      newPassphrase,
      newSalt,
      this._params.argon2Params,
    );

    // Re-encrypt DEK and X25519 private key with new master key
    const encryptedDek = aesGcm.serialize(
      aesGcm.encrypt(newMasterKey, this._dek),
    );
    const encryptedX25519Private = aesGcm.serialize(
      aesGcm.encrypt(newMasterKey, this._x25519Secret),
    );
    shredAll(newMasterKey);

    const newParams: VaultParams = {
      argon2Salt: newSalt,
      argon2Params: this._params.argon2Params,
      encryptedDek,
      encryptedX25519Private,
      x25519Public: this._params.x25519Public,
    };
    this._params = newParams;
    return newParams;
  }

  shred(): void {
    shredAll(this._dek, this._x25519Secret);
    this._shredded = true;
  }
}

/**
 * Create a new vault from a passphrase. Called during onboarding.
 * Returns both the Vault handle and the VaultParams to send to the server.
 */
export async function createVault(
  passphrase: string,
  params?: Partial<Argon2Params>,
): Promise<{ vault: Vault; params: VaultParams }> {
  const argon2Params: Argon2Params = { ...DEFAULT_ARGON2_PARAMS, ...params };
  const salt = generateSalt();

  // Step 1: Derive master key from passphrase
  const masterKey = await deriveKey(passphrase, salt, argon2Params);

  // Step 2: Derive DEK and X25519 keypair from master key via HKDF
  const dek = deriveSubkey(masterKey, DEK_CONTEXT);
  const x25519Seed = deriveSubkey(masterKey, X25519_CONTEXT);
  const keyPair = generateKeyPair(x25519Seed);
  shredAll(x25519Seed);

  // Step 3: Encrypt DEK and X25519 private key with master key
  const encryptedDek = aesGcm.serialize(aesGcm.encrypt(masterKey, dek));
  const encryptedX25519Private = aesGcm.serialize(
    aesGcm.encrypt(masterKey, keyPair.secretKey),
  );
  shredAll(masterKey);

  const vaultParams: VaultParams = {
    argon2Salt: salt,
    argon2Params,
    encryptedDek,
    encryptedX25519Private,
    x25519Public: keyPair.publicKey,
  };

  return {
    vault: new VaultImpl(dek, keyPair.secretKey, vaultParams),
    params: vaultParams,
  };
}

/**
 * Unlock an existing vault with a passphrase. Called on login.
 * Fetches VaultParams from the server, derives master key, decrypts DEK.
 * Throws if the passphrase is wrong (AES-GCM auth tag mismatch).
 */
export async function unlockVault(
  passphrase: string,
  params: VaultParams,
): Promise<Vault> {
  // Re-derive master key from passphrase + stored salt
  const masterKey = await deriveKey(
    passphrase,
    params.argon2Salt,
    params.argon2Params,
  );

  // Decrypt DEK (throws on wrong passphrase - auth tag mismatch)
  const dekBlob = aesGcm.deserialize(params.encryptedDek);
  const dek = aesGcm.decrypt(masterKey, dekBlob);

  // Decrypt X25519 private key
  const x25519Blob = aesGcm.deserialize(params.encryptedX25519Private);
  const x25519Secret = aesGcm.decrypt(masterKey, x25519Blob);
  shredAll(masterKey);

  return new VaultImpl(dek, x25519Secret, params);
}
