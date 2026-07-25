/**
 * Client-side passphrase vault for wrapping the keys.txt secret hex blob.
 * Server only ever stores opaque ciphertext + nonce + salt — never plaintext keys.
 *
 * PBKDF2 (Web Crypto) → AES-GCM encrypt/decrypt.
 */

const KDF = 'pbkdf2';
const PBKDF2_ITERATIONS = 310000;
const SALT_BYTES = 16;
const IV_BYTES = 12;

function toBase64(bytes) {
  let binary = '';
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  for (let i = 0; i < arr.length; i += 1) binary += String.fromCharCode(arr[i]);
  return btoa(binary);
}

function fromBase64(b64) {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}

async function deriveAesKey(passphrase, saltBytes) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, [
    'deriveKey',
  ]);
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: saltBytes,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256',
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * @param {string} passphrase
 * @param {string} secretKeysJson - JSON string of the secret-key hex array (or keys blob)
 * @returns {Promise<{ ciphertext: string, nonce: string, salt: string, kdf: string }>}
 */
export async function encryptVaultPayload(passphrase, secretKeysJson) {
  if (!passphrase || typeof passphrase !== 'string') {
    throw new Error('Passphrase is required');
  }
  if (typeof secretKeysJson !== 'string') {
    throw new Error('secretKeysJson must be a string');
  }

  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const key = await deriveAesKey(passphrase, salt);
  const plaintext = new TextEncoder().encode(secretKeysJson);
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);

  return {
    ciphertext: toBase64(new Uint8Array(encrypted)),
    nonce: toBase64(iv),
    salt: toBase64(salt),
    kdf: KDF,
  };
}

/**
 * @param {string} passphrase
 * @param {{ ciphertext: string, nonce: string, salt: string, kdf?: string }} vaultRecord
 * @returns {Promise<string>} plaintext secretKeysJson
 */
export async function decryptVaultPayload(passphrase, vaultRecord) {
  if (!passphrase || typeof passphrase !== 'string') {
    throw new Error('Passphrase is required');
  }
  if (!vaultRecord?.ciphertext || !vaultRecord?.nonce || !vaultRecord?.salt) {
    throw new Error('Incomplete vault record');
  }

  const salt = fromBase64(vaultRecord.salt);
  const iv = fromBase64(vaultRecord.nonce);
  const ciphertext = fromBase64(vaultRecord.ciphertext);
  const key = await deriveAesKey(passphrase, salt);

  try {
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
    return new TextDecoder().decode(decrypted);
  } catch {
    throw new Error('Wrong passphrase or corrupted vault data');
  }
}
