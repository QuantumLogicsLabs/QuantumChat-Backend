import mongoose from 'mongoose';
import path from 'path';
import { getStorage, isSafeImageMime, newObjectName, safeImageContentType } from '../middleware/upload.js';
import Story from '../models/Story.js';
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

function parseStoryStatus(raw) {
  const s = String(raw || 'published').toLowerCase();
  if (s === 'draft' || s === 'scheduled' || s === 'published') return s;
  return null;
}

function clampTtlMs(raw) {
  let ttlMs = Number(raw || 0);
  if (!Number.isFinite(ttlMs) || ttlMs <= 0) ttlMs = Story.ttlMs;
  return Math.min(Math.max(ttlMs, Story.minTtlMs), Story.maxTtlMs);
}

function parsePublishAt(raw) {
  if (raw == null || raw === '') return null;
  const d = new Date(raw);
  if (Number.isNaN(d.getTime())) return null;
  return d;
}

function storyOwnerPayload(story, userDoc) {
  return {
    ...story.toPublicJSON(),
    user: {
      id: userDoc?._id || story.user,
      username: userDoc?.username || 'User',
      hasAvatar: Boolean(userDoc?.avatarPath),
    },
  };
}

function assertLiveOrOwner(story, viewerId) {
  const status = story.status || 'published';
  const ownerId = String(story.user?._id || story.user);
  if (status === 'published') return true;
  return ownerId === String(viewerId);
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
  if (!Array.isArray(list) || !list.length) return null;
  const out = [];
  for (const item of list) {
    if (
      !item ||
      !mongoose.isValidObjectId(item.user) ||
      typeof item.ciphertext !== 'string' ||
      typeof item.nonce !== 'string' ||
      !HEX_64.test(item.ephemeralPublicKey || '') ||
      !HEX_64.test(item.targetPublicKey || '')
    ) {
      return null;
    }
    out.push({
      user: item.user,
      ciphertext: item.ciphertext,
      nonce: item.nonce,
      ephemeralPublicKey: String(item.ephemeralPublicKey).toLowerCase(),
      targetPublicKey: String(item.targetPublicKey).toLowerCase(),
    });
  }
  return out;
}

export async function createStory(req, res) {
  try {
    if (!req.file?.buffer) {
      return res.status(400).json({ success: false, error: 'Media file is required' });
    }

    const sealed = parseSealedFlag(req.body.sealed);
    const declaredMime = typeof req.body.mimetype === 'string' ? req.body.mimetype.trim() : '';
    const mimetype = sealed && declaredMime ? declaredMime : req.file.mimetype;
    const mediaType =
      mediaTypeFromMime(mimetype) ||
      (['image', 'video', 'audio', 'text'].includes(String(req.body.mediaType || ''))
        ? String(req.body.mediaType)
        : null);

    if (!mediaType) {
      return res.status(400).json({ success: false, error: 'Unsupported media type' });
    }

    let durationMs = Number(req.body.durationMs || 0);
    if (!Number.isFinite(durationMs) || durationMs < 0) durationMs = 0;
    if ((mediaType === 'video' || mediaType === 'audio') && durationMs > Story.maxDurationMs) {
      return res.status(400).json({
        success: false,
        error: `Stories must be ${Story.maxDurationMs / 1000} seconds or shorter`,
      });
    }
    if (mediaType === 'image') durationMs = 0;

    let ttlMs = clampTtlMs(req.body.ttlMs);

    const status = parseStoryStatus(req.body.status);
    if (!status) {
      return res.status(400).json({ success: false, error: 'Invalid status (draft, scheduled, or published)' });
    }

    let publishAt = null;
    if (status === 'scheduled') {
      publishAt = parsePublishAt(req.body.publishAt);
      if (!publishAt || publishAt.getTime() <= Date.now() + 30_000) {
        return res.status(400).json({
          success: false,
          error: 'Scheduled stories need a publishAt at least 30 seconds in the future',
        });
      }
    }

    const caption =
      sealed
        ? ''
        : typeof req.body.caption === 'string'
          ? req.body.caption.trim().slice(0, 200)
          : '';

    const allowReplies = parseSealedFlag(
      req.body.allowReplies === undefined ? true : req.body.allowReplies
    );

    let envelopes;
    let contentIv;
    if (sealed) {
      envelopes = parseEnvelopes(req.body.envelopes);
      if (!envelopes) {
        return res.status(400).json({
          success: false,
          error: 'Sealed stories require per-viewer X5 envelopes',
        });
      }
      const selfIncluded = envelopes.some((e) => String(e.user) === String(req.user._id));
      if (!selfIncluded) {
        return res.status(400).json({
          success: false,
          error: 'Sealed stories must include an envelope for the author',
        });
      }

      const storyPrivacy = req.user.privacy?.story || 'everyone';
      if (storyPrivacy !== 'everyone') {
        const authorId = String(req.user._id);
        const friendSet = new Set((req.user.friends || []).map((id) => String(id)));
        const selectedSet = new Set(
          (req.user.privacy?.storyViewers || []).map((id) => String(id))
        );
        const disallowed = envelopes.find((e) => {
          const viewerId = String(e.user);
          if (viewerId === authorId) return false;
          if (storyPrivacy === 'nobody') return true;
          if (storyPrivacy === 'friends') return !friendSet.has(viewerId);
          if (storyPrivacy === 'selected') return !selectedSet.has(viewerId);
          return false;
        });
        if (disallowed) {
          return res.status(400).json({
            success: false,
            error: 'Story envelopes include a viewer outside your story privacy audience',
          });
        }
      }
      contentIv = typeof req.body.contentIv === 'string' ? req.body.contentIv.slice(0, 128) : '';
      if (!contentIv) {
        return res.status(400).json({ success: false, error: 'contentIv is required for sealed stories' });
      }
    }

    const ext = path.extname(req.file.originalname || '').toLowerCase();
    const safeExt = ext === '.svg' ? '' : ext;
    const objectName = newObjectName('stories', safeExt);
    const stored = await getStorage().put(
      req.file.buffer,
      objectName,
      mimetype || req.file.mimetype || 'application/octet-stream',
      String(req.user._id)
    );

    const now = Date.now();
    let expiresAt;
    if (status === 'draft') {
      expiresAt = new Date(now + Story.draftRetentionMs);
    } else if (status === 'scheduled') {
      expiresAt = new Date(publishAt.getTime() + ttlMs);
    } else {
      expiresAt = new Date(now + ttlMs);
    }

    const story = await Story.create({
      user: req.user._id,
      mediaType,
      filename: req.file.originalname || objectName,
      mimetype: mimetype || req.file.mimetype,
      size: req.file.size,
      storagePath: stored.key,
      storageProvider: stored.provider,
      durationMs,
      caption,
      ttlMs,
      status,
      publishAt: status === 'scheduled' ? publishAt : null,
      expiresAt,
      sealed,
      allowReplies,
      contentIv: sealed ? contentIv : undefined,
      envelopes: sealed ? envelopes : undefined,
    });

    const payload = storyOwnerPayload(story, req.user);

    if (status === 'published') {
      const io = req.app.get('io');
      if (io) io.emit('story:new', payload);
    }

    res.status(201).json({ success: true, data: payload });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

export async function listStories(req, res) {
  try {
    const now = new Date();
    const blocked = new Set((req.user.blockedUsers || []).map(String));
    const stories = await Story.find({
      status: { $nin: ['draft', 'scheduled'] },
      expiresAt: { $gt: now },
    })
      .sort({ createdAt: -1 })
      .populate('user', 'username avatarPath');

    const viewerId = String(req.user._id);
    const filtered = [];
    for (const story of stories) {
      const ownerId = String(story.user?._id || story.user);
      if (blocked.has(ownerId)) continue;
      if (await areUsersBlocked(req.user._id, ownerId)) continue;
      if (story.sealed) {
        const envelopes = story.envelopes || [];
        const allowed = envelopes.some((e) => String(e.user) === viewerId);
        if (!allowed) continue;
      }
      filtered.push({
        ...(() => {
          const pub = story.toPublicJSON();
          if (pub.sealed && Array.isArray(pub.envelopes)) {
            pub.envelopes = pub.envelopes.filter((e) => String(e.user) === viewerId);
          }
          return pub;
        })(),
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

/** Owner-only drafts + scheduled stories. */
export async function listMyDrafts(req, res) {
  try {
    const now = new Date();
    const stories = await Story.find({
      user: req.user._id,
      status: { $in: ['draft', 'scheduled'] },
      expiresAt: { $gt: now },
    }).sort({ updatedAt: -1 });

    res.json({
      success: true,
      data: stories.map((s) => storyOwnerPayload(s, req.user)),
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}
export async function getStoryById(req, res) {
  try {
    const { id } = req.params;
    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).json({ success: false, error: 'Invalid story id' });
    }
    const story = await Story.findById(id).populate('user', 'username avatarPath');
    if (!story || story.expiresAt <= new Date()) {
      return res.status(404).json({ success: false, error: 'Story not found or expired' });
    }
    const ownerId = String(story.user?._id || story.user);
    const viewerId = String(req.user._id);
    if (!assertLiveOrOwner(story, viewerId)) {
      return res.status(404).json({ success: false, error: 'Story not found or expired' });
    }
    if (await areUsersBlocked(req.user._id, ownerId)) {
      return res.status(403).json({ success: false, error: 'Not allowed' });
    }
    if ((story.status || 'published') === 'published' && story.sealed) {
      const envelopes = story.envelopes || [];
      const allowed = envelopes.some((e) => String(e.user) === viewerId);
      if (!allowed) {
        return res.status(404).json({ success: false, error: 'Story not found or expired' });
      }
    }
    const pub = story.toPublicJSON();
    if (pub.sealed && Array.isArray(pub.envelopes) && ownerId !== viewerId) {
      pub.envelopes = pub.envelopes.filter((e) => String(e.user) === viewerId);
    }
    res.json({
      success: true,
      data: {
        ...pub,
        user: {
          id: ownerId,
          username: story.user?.username || 'User',
          hasAvatar: Boolean(story.user?.avatarPath),
        },
      },
    });
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
    const viewerId = String(req.user._id);
    if (!assertLiveOrOwner(story, viewerId)) {
      return res.status(404).json({ success: false, error: 'Story not found or expired' });
    }
    if (await areUsersBlocked(req.user._id, story.user)) {
      return res.status(403).json({ success: false, error: 'Not allowed' });
    }

    if (story.sealed) {
      const envelopes = story.envelopes || [];
      const allowed = envelopes.some((e) => String(e.user) === viewerId);
      if (!allowed) {
        return res.status(403).json({
          success: false,
          error: 'Not in sealed story audience',
          sealed: true,
        });
      }
    }

    const bytes = await getStorage().read(story.storagePath);
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
    res.send(bytes);
  } catch (err) {
    if (!res.headersSent) {
      res.status(404).json({ success: false, error: 'Media missing' });
    }
  }
}

/** Records that the current user viewed a story. Called once per open. */
export async function markStoryViewed(req, res) {
  try {
    const { id } = req.params;
    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).json({ success: false, error: 'Invalid story id' });
    }
    const story = await Story.findById(id);
    if (!story || story.expiresAt <= new Date() || (story.status || 'published') !== 'published') {
      return res.status(404).json({ success: false, error: 'Story not found or expired' });
    }
    const ownerId = String(story.user);
    const viewerId = String(req.user._id);

    if (viewerId === ownerId) {
      return res.json({ success: true, data: { recorded: false } });
    }
    if (await areUsersBlocked(req.user._id, ownerId)) {
      return res.status(403).json({ success: false, error: 'Not allowed' });
    }

    const result = await Story.updateOne(
      { _id: id, 'views.user': { $ne: req.user._id } },
      { $push: { views: { user: req.user._id, viewedAt: new Date() } } }
    );
    const wasNewView = result.modifiedCount === 1;

    if (wasNewView) {
      const io = req.app.get('io');
      if (io) {
        const updated = await Story.findById(id).select('views');
        io.to(ownerId).emit('story:viewed', {
          storyId: String(story._id),
          viewer: {
            id: viewerId,
            username: req.user.username,
            hasAvatar: Boolean(req.user.avatarPath),
          },
          viewedAt: new Date().toISOString(),
          viewerCount: updated.views.length,
        });
      }
    }

    res.json({ success: true, data: { recorded: wasNewView } });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

/** Returns the viewer list for a story. Owner-only. */
export async function getStoryViewers(req, res) {
  try {
    const { id } = req.params;
    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).json({ success: false, error: 'Invalid story id' });
    }
    const story = await Story.findById(id).populate('views.user', 'username avatarPath');
    if (!story) {
      return res.status(404).json({ success: false, error: 'Story not found' });
    }
    if (String(story.user) !== String(req.user._id)) {
      return res.status(403).json({ success: false, error: 'Not authorized' });
    }

    const viewers = (story.views || [])
      .slice()
      .sort((a, b) => new Date(b.viewedAt) - new Date(a.viewedAt))
      .map((v) => ({
        id: String(v.user?._id || v.user),
        username: v.user?.username || 'User',
        hasAvatar: Boolean(v.user?.avatarPath),
        viewedAt: v.viewedAt,
      }));

    res.json({ success: true, data: { viewerCount: viewers.length, viewers } });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

/** Update draft/scheduled settings (ttl, schedule, allowReplies, caption). */
export async function updateStory(req, res) {
  try {
    const { id } = req.params;
    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).json({ success: false, error: 'Invalid story id' });
    }
    const story = await Story.findById(id);
    if (!story) return res.status(404).json({ success: false, error: 'Story not found' });
    if (String(story.user) !== String(req.user._id)) {
      return res.status(403).json({ success: false, error: 'Not authorized' });
    }
    if (!['draft', 'scheduled'].includes(story.status || '')) {
      return res.status(400).json({ success: false, error: 'Only drafts or scheduled stories can be edited' });
    }

    if (req.body.ttlMs !== undefined) {
      story.ttlMs = clampTtlMs(req.body.ttlMs);
    }
    if (req.body.allowReplies !== undefined) {
      story.allowReplies = parseSealedFlag(req.body.allowReplies);
    }
    if (!story.sealed && typeof req.body.caption === 'string') {
      story.caption = req.body.caption.trim().slice(0, 200);
    }

    const nextStatus = req.body.status !== undefined ? parseStoryStatus(req.body.status) : story.status;
    if (!nextStatus || nextStatus === 'published') {
      // Publishing goes through publishStory
      if (req.body.status === 'published') {
        return res.status(400).json({
          success: false,
          error: 'Use POST /stories/:id/publish to publish',
        });
      }
      if (!nextStatus) {
        return res.status(400).json({ success: false, error: 'Invalid status' });
      }
    }

    if (nextStatus === 'draft') {
      story.status = 'draft';
      story.publishAt = null;
      story.expiresAt = new Date(Date.now() + Story.draftRetentionMs);
    } else if (nextStatus === 'scheduled') {
      const publishAt =
        req.body.publishAt !== undefined ? parsePublishAt(req.body.publishAt) : story.publishAt;
      if (!publishAt || publishAt.getTime() <= Date.now() + 30_000) {
        return res.status(400).json({
          success: false,
          error: 'Scheduled stories need a publishAt at least 30 seconds in the future',
        });
      }
      story.status = 'scheduled';
      story.publishAt = publishAt;
      story.expiresAt = new Date(publishAt.getTime() + story.ttlMs);
    }

    await story.save();
    res.json({ success: true, data: storyOwnerPayload(story, req.user) });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

/** Publish a draft or scheduled story immediately. */
export async function publishStory(req, res) {
  try {
    const { id } = req.params;
    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).json({ success: false, error: 'Invalid story id' });
    }
    const story = await Story.findById(id);
    if (!story) return res.status(404).json({ success: false, error: 'Story not found' });
    if (String(story.user) !== String(req.user._id)) {
      return res.status(403).json({ success: false, error: 'Not authorized' });
    }
    if (!['draft', 'scheduled'].includes(story.status || '')) {
      return res.status(400).json({ success: false, error: 'Story is already published' });
    }

    if (req.body.ttlMs !== undefined) {
      story.ttlMs = clampTtlMs(req.body.ttlMs);
    }
    if (req.body.allowReplies !== undefined) {
      story.allowReplies = parseSealedFlag(req.body.allowReplies);
    }

    const now = Date.now();
    story.status = 'published';
    story.publishAt = new Date(now);
    story.expiresAt = new Date(now + (story.ttlMs || Story.ttlMs));
    await story.save();

    const payload = storyOwnerPayload(story, req.user);
    const io = req.app.get('io');
    if (io) io.emit('story:new', payload);

    res.json({ success: true, data: payload });
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
      if (story.storagePath) await getStorage().delete(story.storagePath);
    } catch {
      // ignore
    }
    const wasPublished = (story.status || 'published') === 'published';
    await Story.deleteOne({ _id: story._id });
    const io = req.app.get('io');
    if (io && wasPublished) io.emit('story:deleted', { id });
    res.json({ success: true, data: { id } });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}
