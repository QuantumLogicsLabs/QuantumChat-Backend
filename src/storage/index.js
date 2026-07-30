import { GoogleDriveStorageAdapter } from './GoogleDriveStorageAdapter.js';
import { MemoryStorageAdapter } from './MemoryStorageAdapter.js';

/** @type {GoogleDriveStorageAdapter | MemoryStorageAdapter | null} */
let cached;

/**
 * Durable blob storage — Google Drive only (no local uploads/ disk).
 * Requires GOOGLE_DRIVE_FOLDER_ID, GOOGLE_SERVICE_ACCOUNT_EMAIL, GOOGLE_PRIVATE_KEY.
 */
/** Accept raw folder id or a Drive share URL containing /folders/<id>. */
function normalizeDriveFolderId(raw) {
  const value = String(raw || '').trim();
  const fromUrl = value.match(/\/folders\/([a-zA-Z0-9_-]+)/);
  return fromUrl ? fromUrl[1] : value.replace(/\?.*$/, '');
}

export function getStorage() {
  if (cached) return cached;
  if (process.env.STORAGE_PROVIDER === 'memory') {
    if (process.env.NODE_ENV !== 'test') {
      throw new Error('Memory storage is restricted to NODE_ENV=test');
    }
    cached = new MemoryStorageAdapter();
    return cached;
  }
  const folderId = normalizeDriveFolderId(process.env.GOOGLE_DRIVE_FOLDER_ID);
  const email = process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL;
  const key = process.env.GOOGLE_PRIVATE_KEY;
  if (!folderId || !email || !key) {
    throw new Error(
      'Google Drive storage requires GOOGLE_DRIVE_FOLDER_ID, GOOGLE_SERVICE_ACCOUNT_EMAIL, and GOOGLE_PRIVATE_KEY'
    );
  }
  cached = new GoogleDriveStorageAdapter(folderId, email, key);
  return cached;
}

export function getStorageProviderName() {
  return process.env.STORAGE_PROVIDER === 'memory' ? 'memory' : 'google-drive';
}

export { GoogleDriveStorageAdapter } from './GoogleDriveStorageAdapter.js';
export { MemoryStorageAdapter } from './MemoryStorageAdapter.js';
