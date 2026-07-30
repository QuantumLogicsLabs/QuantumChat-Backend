/**
 * @typedef {{ key: string, provider: 'local' | 'google-drive' | 'memory' }} StoredObject
 *
 * @typedef {object} StorageAdapter
 * @property {() => Promise<void>} ensureReady
 * @property {(buffer: Buffer, name: string, mimeType: string, userId: string) => Promise<StoredObject>} put
 * @property {(key: string) => Promise<Buffer>} read
 * @property {(key: string) => Promise<void>} delete
 */

export {};
