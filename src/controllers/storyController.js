import fs from 'fs';
import mongoose from 'mongoose';
import Story from '../models/Story.js';
import { resolveUploadPath, isSafeImageMime, safeImageContentType } from '../middleware/upload.js';
import { areUsersBlocked } from './userController.js';

const HEX_64 = /^[0-9a-f]{64}$/i;

function mediaTypeFromMime(mimetype = '') {
  if (mimetype.startsWith('image/')) return 'image';
  if (mimetype.startsWith('video/')) return 'video';
  if (mimetype.startsWith('audio/')) return 'audio';
  return null;
}

function parseSealedFlag(value) {
  if (value === true || value === 1) return true;
  const s = String(value || '').toLowerCase();
  return s === 'true' || s === '1' || s === 'yes';
}

function parseEnvelopes(raw) {
  let list = raw;
  if (typeof raw === 'string') {
    try {
      list = JSON.parse(raw);
    } catch {
      return null;
    }
  }
  if (!Array.isArray(list) || list.length < 1) return null;
  const envelopes = [];
  for (const item of list) {
    if (!item || !mongoose.isValidObjectId(item.user)) return null;
    if (
      typeof item.ciphertext !== 'string' ||
      typeof item.nonce !== 'string' ||
      !HEX_64.test(item.ephemeralPublicKey || '') ||
      !HEX_64.test(item.targetPublicKey || '')
    ) {
      return null;
    }
    envelopes.push({
      user: item.user,
      ciphertext: item.ciphertext,
      nonce: item.nonce,
      ephemeralPublicKey: String(item.ephemeralPublicKey).toLowerCase(),
      targetPublicKey: String(item.targetPublicKey).toLowerCase(),
    });
  }
  return envelopes;
}

export async function createStory(req, res) {
  try {
    if (!req.file) {
      return res.status(400).json({ success: false, error: 'Media file is required' });
    }

    const sealed = parseSealedFlag(req.body.sealed);
    const declaredMime = typeof req.body.mimetype === 'string' ? req.body.mimetype.trim() : '';
    const mimetype = sealed && declaredMime ? declaredMime : req.file.mimetype;
    const mediaType =
      mediaTypeFromMime(mimetype) ||
      (['image', 'video', 'audio'].includes(String(req.body.mediaType || ''))
        ? String(req.body.mediaType)
        : null);

    if (!mediaType) {
      fs.unlink(req.file.path, () => {});
      return res.status(400).json({ success: false, error: 'Unsupported media type' });
    }

    let durationMs = Number(req.body.durationMs || 0);
    if (!Number.isFinite(durationMs) || durationMs < 0) durationMs = 0;
    if ((mediaType === 'video' || mediaType === 'audio') && durationMs > Story.maxDurationMs) {
      fs.unlink(req.file.path, () => {});
      return res.status(400).json({
        success: false,
        error: `Stories must be ${Story.maxDurationMs / 1000} seconds or shorter`,
      });
    }
    if (mediaType === 'image') durationMs = 0;

    const caption =
      sealed
        ? ''
        : typeof req.body.caption === 'string'
          ? req.body.caption.trim().slice(0, 200)
          : '';

    let envelopes;
    let contentIv;
    if (sealed) {
      envelopes = parseEnvelopes(req.body.envelopes);
      if (!envelopes) {
        fs.unlink(req.file.path, () => {});
        return res.status(400).json({
          success: false,
          error: 'Sealed stories require per-viewer X5 envelopes',
        });
      }
      const selfIncluded = envelopes.some((e) => String(e.user) === String(req.user._id));
      if (!selfIncluded) {
        fs.unlink(req.file.path, () => {});
        return res.status(400).json({
          success: false,
          error: 'Sealed stories must include an envelope for the author',
        });
      }
      contentIv = typeof req.body.contentIv === 'string' ? req.body.contentIv.slice(0, 128) : '';
      if (!contentIv) {
        fs.unlink(req.file.path, () => {});
        return res.status(400).json({ success: false, error: 'contentIv is required for sealed stories' });
      }
    }

    const relativePath = `stories/${req.file.filename}`;
    const story = await Story.create({
      user: req.user._id,
      mediaType,
      filename: req.file.originalname || req.file.filename,
      mimetype: mimetype || req.file.mimetype,
      size: req.file.size,
      storagePath: relativePath,
      durationMs,
      caption,
      expiresAt: new Date(Date.now() + Story.ttlMs),
      sealed,
      contentIv: sealed ? contentIv : undefined,
      envelopes: sealed ? envelopes : undefined,
    });

    const payload = {
      ...story.toPublicJSON(),
      user: {
        id: req.user._id,
        username: req.user.username,
        hasAvatar: Boolean(req.user.avatarPath),
      },
    };

    const io = req.app.get('io');
    if (io) io.emit('story:new', payload);

    res.status(201).json({ success: true, data: payload });
  } catch (err) {
    if (req.file?.path) fs.unlink(req.file.path, () => {});
    res.status(500).json({ success: false, error: err.message });
  }
}

export async function listStories(req, res) {
  try {
    const now = new Date();
    const blocked = new Set((req.user.blockedUsers || []).map(String));
    const stories = await Story.find({ expiresAt: { $gt: now } })
      .sort({ createdAt: -1 })
      .populate('user', 'username avatarPath');

    const viewerId = String(req.user._id);
    const filtered = [];
    for (const story of stories) {
      const ownerId = String(story.user?._id || story.user);
      if (blocked.has(ownerId)) continue;
      if (await areUsersBlocked(req.user._id, ownerId)) continue;
      // Sealed stories are only listed for viewers who have an envelope
      // (otherwise the client can only show “no envelope for your keys”).
      if (story.sealed) {
        const envelopes = story.envelopes || [];
        const allowed = envelopes.some((e) => String(e.user) === viewerId);
        if (!allowed) continue;
      }
      filtered.push({
        ...story.toPublicJSON(),
        user: {
          id: ownerId,
          username: story.user?.username || 'User',
          hasAvatar: Boolean(story.user?.avatarPath),
        },
      });
    }

    res.json({ success: true, data: filtered });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

export async function getStoryMedia(req, res) {
  try {
    const { id } = req.params;
    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).json({ success: false, error: 'Invalid story id' });
    }
    const story = await Story.findById(id);
    if (!story || story.expiresAt <= new Date()) {
      return res.status(404).json({ success: false, error: 'Story not found or expired' });
    }
    if (await areUsersBlocked(req.user._id, story.user)) {
      return res.status(403).json({ success: false, error: 'Not allowed' });
    }

    if (story.sealed) {
      const envelopes = story.envelopes || [];
      const allowed = envelopes.some((e) => String(e.user) === String(req.user._id));
      if (!allowed) {
        return res.status(403).json({
          success: false,
          error: 'Not in sealed story audience',
          sealed: true,
        });
      }
    }

    const filePath = resolveUploadPath(story.storagePath);
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ success: false, error: 'Media missing' });
    }
    if (story.sealed) {
      res.setHeader('Content-Type', 'application/octet-stream');
      res.setHeader('Content-Disposition', 'attachment');
      res.setHeader('X-QuantumChat-Sealed', '1');
    } else if (isSafeImageMime(story.mimetype)) {
      res.setHeader('Content-Type', safeImageContentType(story.mimetype));
      res.setHeader('Content-Disposition', 'inline');
    } else if (
      String(story.mimetype || '').startsWith('video/') ||
      String(story.mimetype || '').startsWith('audio/')
    ) {
      res.setHeader('Content-Type', story.mimetype);
      res.setHeader('Content-Disposition', 'inline');
    } else {
      res.setHeader('Content-Type', 'application/octet-stream');
      res.setHeader('Content-Disposition', 'attachment');
    }
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Cache-Control', 'private, max-age=300');
    fs.createReadStream(filePath).pipe(res);
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

export async function deleteStory(req, res) {
  try {
    const { id } = req.params;
    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).json({ success: false, error: 'Invalid story id' });
    }
    const story = await Story.findById(id);
    if (!story) return res.status(404).json({ success: false, error: 'Story not found' });
    if (story.user.toString() !== req.user._id.toString()) {
      return res.status(403).json({ success: false, error: 'Not authorized' });
    }
    try {
      fs.unlink(resolveUploadPath(story.storagePath), () => {});
    } catch {
      // ignore
    }
    await Story.deleteOne({ _id: story._id });
    const io = req.app.get('io');
    if (io) io.emit('story:deleted', { id });
    res.json({ success: true, data: { id } });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}
