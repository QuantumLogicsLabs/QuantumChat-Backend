import crypto from 'crypto';

/**
 * Process-local storage used only by automated tests. This keeps security
 * suites deterministic and offline without weakening the production rule
 * that durable blobs must use Google Drive.
 */
export class MemoryStorageAdapter {
  constructor() {
    this.objects = new Map();
  }

  async ensureReady() {}

  async put(buffer, name, _mimeType, _userId) {
    const key = `${crypto.randomUUID()}:${String(name || 'blob')}`;
    this.objects.set(key, Buffer.from(buffer));
    return { key, provider: 'memory' };
  }

  async read(key) {
    const value = this.objects.get(key);
    if (!value) {
      const error = new Error('Stored object not found');
      error.code = 'ENOENT';
      throw error;
    }
    return Buffer.from(value);
  }

  async delete(key) {
    this.objects.delete(key);
  }
}
