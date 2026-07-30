import multer from 'multer';
import path from 'path';
import crypto from 'crypto';
import { getStorage } from '../storage/index.js';

/** Raster images only — SVG is rejected (scriptable when opened as a document). */
export const SAFE_IMAGE_MIMES = new Set([
  'image/jpeg',
  'image/png',
  'image/webp',
  'image/gif',
]);

const SAFE_IMAGE_EXTS = new Set(['.jpg', '.jpeg', '.png', '.webp', '.gif']);

export function isSafeImageMime(mime) {
  return SAFE_IMAGE_MIMES.has(String(mime || '').toLowerCase());
}

export function safeImageContentType(mime, fallback = 'image/jpeg') {
  const normalized = String(mime || '').toLowerCase();
  return SAFE_IMAGE_MIMES.has(normalized) ? normalized : fallback;
}

function rasterImageFilter(label) {
  return (req, file, cb) => {
    const mime = String(file.mimetype || '').toLowerCase();
    const ext = path.extname(file.originalname || '').toLowerCase();
    if (ext === '.svg' || mime === 'image/svg+xml' || !SAFE_IMAGE_MIMES.has(mime)) {
      return cb(new Error(`${label} must be JPEG, PNG, WebP, or GIF`));
    }
    if (ext && !SAFE_IMAGE_EXTS.has(ext)) {
      return cb(new Error(`${label} must be JPEG, PNG, WebP, or GIF`));
    }
    cb(null, true);
  };
}

// Memory staging only — durable blobs go to Google Drive via getStorage().
const memory = multer.memoryStorage();

export const upload = multer({
  storage: memory,
  limits: { fileSize: 15 * 1024 * 1024 },
});

export const avatarUpload = multer({
  storage: memory,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: rasterImageFilter('Avatar'),
});

export const groupPhotoUpload = multer({
  storage: memory,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: rasterImageFilter('Group photo'),
});

export const storyUpload = multer({
  storage: memory,
  limits: { fileSize: 40 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const type = String(file.mimetype || '').toLowerCase();
    const ext = path.extname(file.originalname || '').toLowerCase();
    if (type === 'image/svg+xml' || ext === '.svg') {
      return cb(new Error('SVG stories are not allowed'));
    }
    if (
      SAFE_IMAGE_MIMES.has(type) ||
      type.startsWith('video/') ||
      type.startsWith('audio/') ||
      type === 'application/octet-stream'
    ) {
      return cb(null, true);
    }
    cb(new Error('Story must be an image, video, or audio file'));
  },
});

/** Display / Drive object name helper (not a filesystem path). */
export function newObjectName(prefix = '', ext = '') {
  const safePrefix = String(prefix || '')
    .replace(/[^a-zA-Z0-9_-]/g, '')
    .slice(0, 64);
  const normalizedExt = String(ext || '').toLowerCase();
  const safeExt = /^\.[a-z0-9]{1,10}$/.test(normalizedExt) ? normalizedExt : '';
  const base = `${crypto.randomUUID()}${safeExt}`;
  return safePrefix ? `${safePrefix}/${base}` : base;
}

export { getStorage };
