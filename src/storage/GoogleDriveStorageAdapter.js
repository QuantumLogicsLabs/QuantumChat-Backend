import { Readable } from 'stream';
import { google } from 'googleapis';

/**
 * Durable blob storage for Vercel via a Shared Drive folder + service account.
 * Keys are Google Drive file ids. Ciphertext only — never store plaintext secrets here.
 */
export class GoogleDriveStorageAdapter {
  /**
   * @param {string} folderId
   * @param {string} serviceAccountEmail
   * @param {string} privateKey
   */
  constructor(folderId, serviceAccountEmail, privateKey) {
    this.folderId = folderId;
    const auth = new google.auth.JWT({
      email: serviceAccountEmail,
      key: String(privateKey || '').replace(/\\n/g, '\n'),
      scopes: ['https://www.googleapis.com/auth/drive'],
    });
    this.drive = google.drive({ version: 'v3', auth });
    this.ready = undefined;
  }

  async ensureReady() {
    this.ready ??= this.drive.files
      .get({
        fileId: this.folderId,
        fields: 'id',
        supportsAllDrives: true,
      })
      .then(() => undefined)
      .catch((error) => {
        this.ready = undefined;
        throw error;
      });
    await this.ready;
  }

  /**
   * @param {Buffer} buffer
   * @param {string} name
   * @param {string} mimeType
   * @param {string} userId
   */
  async put(buffer, name, mimeType, userId) {
    await this.ensureReady();
    const response = await this.drive.files.create({
      requestBody: {
        name,
        parents: [this.folderId],
        appProperties: { quantumChatUserId: String(userId || '') },
      },
      media: {
        mimeType: mimeType || 'application/octet-stream',
        body: Readable.from(buffer),
      },
      fields: 'id',
      supportsAllDrives: true,
    });
    if (!response.data.id) throw new Error('Google Drive did not return a file id');
    return { key: response.data.id, provider: 'google-drive' };
  }

  async read(key) {
    await this.ensureReady();
    const response = await this.drive.files.get(
      { fileId: key, alt: 'media', supportsAllDrives: true },
      { responseType: 'arraybuffer' }
    );
    return Buffer.from(response.data);
  }

  async delete(key) {
    if (!key) return;
    try {
      await this.ensureReady();
      await this.drive.files.delete({ fileId: key, supportsAllDrives: true });
    } catch {
      // best-effort (already gone / permission)
    }
  }
}
