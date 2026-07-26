import fs from 'fs';
import crypto from 'crypto';
import mongoose from 'mongoose';
import Message from '../models/Message.js';
import Attachment from '../models/Attachment.js';
import { areUsersBlocked } from './userController.js';
import { resolveUploadPath } from '../middleware/upload.js';
import User from '../models/User.js';
import Group from '../models/Group.js';
import Story from '../models/Story.js';
import { sealForPublicKey } from '../utils/sealedBox.js';
import { isUserOnline } from '../socket/index.js';
import { notifyUser } from '../services/pushService.js';
import { incrementCiphertextsRelayed } from '../services/blindnessStats.js';
import { resolveExpiresAt, notExpiredFilter } from '../utils/messageExpiry.js';
import { toObjectId } from '../utils/toObjectId.js';

const HEX_64 = /^[0-9a-f]{64}$/i;
const ATTACHMENT_POPULATE =
  'filename mimetype size nonce ephemeralPublicKey targetPublicKey forSenderNonce forSenderEphemeralPublicKey forSenderTargetPublicKey';

function validateEnvelope(envelope) {
  return (
    envelope &&
    typeof envelope.ciphertext === 'string' &&
    typeof envelope.nonce === 'string' &&
    HEX_64.test(envelope.ephemeralPublicKey || '') &&
    HEX_64.test(envelope.targetPublicKey || '')
  );
}

function normalizeEnvelope(envelope) {
  return {
    ...envelope,
    ephemeralPublicKey: String(envelope.ephemeralPublicKey).toLowerCase(),
    targetPublicKey: String(envelope.targetPublicKey).toLowerCase(),
  };
}

function toClientMessage(doc) {
  const message = typeof doc.toObject === 'function' ? doc.toObject() : { ...doc };
  message.id = message._id;
  if (message.attachment && typeof message.attachment === 'object') {
    message.attachment = {
      ...message.attachment,
      id: message.attachment._id || message.attachment.id,
    };
  }
  if (message.group) message.group = message.group._id || message.group;
  if (message.replyToStory) message.replyToStory = message.replyToStory.toString();
  if (message.replyTo && typeof message.replyTo === 'object') {
    message.replyTo = {
      ...message.replyTo,
      id: message.replyTo._id || message.replyTo.id,
      from: message.replyTo.from?.toString?.() || message.replyTo.from,
    };
  } else if (message.replyTo) {
    message.replyTo = { id: message.replyTo };
  }
  message.reactions = (message.reactions || []).map((r) => ({
    user: r.user?.toString?.() || String(r.user),
    forRecipient: r.forRecipient,
    forSender: r.forSender,
    emoji: r.emoji || undefined,
    createdAt: r.createdAt,
  }));
  if (Array.isArray(message.envelopes)) {
    message.envelopes = message.envelopes.map((e) => ({
      ...e,
      user: e.user?.toString?.() || String(e.user),
    }));
  }
  if (typeof message.content === 'string') {
    message.content = message.content;
  }
  return message;
}

function emitToParticipants(io, message, event, payload) {
  if (!io || !message) return;
  const from = message.from?.toString?.() || String(message.from);
  const to = message.to ? message.to.toString() : null;
  io.to(from).emit(event, payload);
  if (to && to !== from) io.to(to).emit(event, payload);
}

async function removeAttachmentFiles(attachmentId) {
  if (!attachmentId) return;
  const attachment = await Attachment.findById(attachmentId);
  if (!attachment) return;
  try {
    fs.unlink(resolveUploadPath(attachment.storagePath), () => {});
    if (attachment.forSenderStoragePath) {
      fs.unlink(resolveUploadPath(attachment.forSenderStoragePath), () => {});
    }
  } catch {
    // best-effort
  }
  await Attachment.deleteOne({ _id: attachment._id });
}

async function assertReplyAllowed(req, replyToId, { to, groupId }) {
  if (!replyToId) return undefined;
  const replyOid = toObjectId(replyToId);
  if (!replyOid) {
    const err = new Error('Invalid replyTo id');
    err.status = 400;
    throw err;
  }
  const parent = await Message.findById(replyOid);
  if (!parent) {
    const err = new Error('Reply target not found');
    err.status = 404;
    throw err;
  }
  const uid = req.user._id.toString();
  if (groupId) {
    if (String(parent.group || '') !== String(groupId)) {
      const err = new Error('Reply must be in the same group');
      err.status = 400;
      throw err;
    }
  } else {
    const peers = [parent.from.toString(), parent.to?.toString()].filter(Boolean);
    if (!peers.includes(uid) || !peers.includes(String(to))) {
      const err = new Error('Reply must be in the same conversation');
      err.status = 400;
      throw err;
    }
  }
  return parent._id;
}
async function assertStoryReplyAllowed(replyToStoryId, userId) {
  if (!replyToStoryId) return undefined;
  const storyOid = toObjectId(replyToStoryId);
  if (!storyOid) {
    const err = new Error('Invalid replyToStory id');
    err.status = 400;
    throw err;
  }
  const story = await Story.findById(storyOid);
  if (!story || story.expiresAt <= new Date()) {
    const err = new Error('Story not found or expired');
    err.status = 404;
    throw err;
  }
  if (story.sealed) {
    const envelopes = story.envelopes || [];
    const allowed = envelopes.some((e) => String(e.user) === String(userId));
    if (!allowed) {
      const err = new Error('Not in this story\'s audience');
      err.status = 403;
      throw err;
    }
  }
  return story._id;
}

function parseForwardPolicy(raw) {
  if (raw == null || typeof raw !== 'object') return undefined;
  const allowForward = raw.allowForward !== false;
  let forwardUntil;
  if (raw.forwardUntil != null && raw.forwardUntil !== '') {
    const d = new Date(raw.forwardUntil);
    if (Number.isNaN(d.getTime())) {
      const err = new Error('forwardPolicy.forwardUntil must be a valid date');
      err.status = 400;
      throw err;
    }
    forwardUntil = d;
  }
  return {
    allowForward,
    ...(forwardUntil ? { forwardUntil } : {}),
  };
}

function evaluateForwardPolicy(original) {
  if (!original) {
    return { allowed: false, reason: 'Original message not found' };
  }
  const policy = original.forwardPolicy || {};
  if (policy.allowForward === false) {
    return { allowed: false, reason: 'Sender disabled forwarding for this message' };
  }
  if (policy.forwardUntil) {
    const until = new Date(policy.forwardUntil);
    if (!Number.isNaN(until.getTime()) && until.getTime() < Date.now()) {
      return { allowed: false, reason: 'Forwarding window for this message has expired' };
    }
  }
  return { allowed: true };
}

function userCanAccessMessage(userId, message) {
  const uid = String(userId);
  if (message.group) return null; // caller must check group membership async
  return String(message.from) === uid || String(message.to) === uid;
}

async function userCanAccessMessageAsync(userId, message) {
  if (!message.group) return userCanAccessMessage(userId, message);
  const group = await Group.findById(message.group).select('members');
  if (!group) return false;
  return group.members.some((m) => String(m) === String(userId));
}

/**
 * When forwarding, load the original and enforce its forwardPolicy.
 * @returns {Promise<{ username?: string, messageId?: * }|undefined>}
 */
async function assertForwardAllowed(req, forwardedFrom) {
  if (!forwardedFrom || typeof forwardedFrom !== 'object') return undefined;
  const messageId = forwardedFrom.messageId;
  const messageOid = toObjectId(messageId);
  const meta = {
    username: String(forwardedFrom.username || '').slice(0, 64) || undefined,
    messageId: messageOid || undefined,
  };
  if (!meta.messageId) return meta;

  const original = await Message.findById(messageOid);
  if (!original) {
    const err = new Error('Original message not found');
    err.status = 404;
    throw err;
  }
  const canAccess = await userCanAccessMessageAsync(req.user._id, original);
  if (!canAccess) {
    const err = new Error('Not allowed to forward this message');
    err.status = 403;
    throw err;
  }
  const verdict = evaluateForwardPolicy(original);
  if (!verdict.allowed) {
    const err = new Error(verdict.reason || 'Forwarding not allowed');
    err.status = 403;
    throw err;
  }
  return meta;
}

export async function checkForwardAllowed(req, res) {
  try {
    const { messageId } = req.params;
    const messageOid = toObjectId(messageId);
    if (!messageOid) {
      return res.status(400).json({ success: false, error: 'Invalid message id' });
    }
    const original = await Message.findById(messageOid);
    if (!original) {
      return res.status(404).json({
        success: false,
        data: { allowed: false, reason: 'Original message not found' },
      });
    }
    const canAccess = await userCanAccessMessageAsync(req.user._id, original);
    if (!canAccess) {
      return res.status(403).json({
        success: false,
        data: { allowed: false, reason: 'Not allowed to forward this message' },
      });
    }
    const verdict = evaluateForwardPolicy(original);
    return res.json({ success: true, data: verdict });
  } catch (err) {
    res.status(err.status || 500).json({ success: false, error: err.message });
  }
}

export async function sendMessage(req, res) {
  try {
   const {
      to,
      forRecipient,
      forSender,
      attachmentId,
      replyTo,
      replyToStory,
      forwardedFrom,
      kind,
      expiresInSeconds,
      forwardPolicy: forwardPolicyRaw,
    } = req.body;
    if (!to || !validateEnvelope(forRecipient) || !validateEnvelope(forSender)) {
      return res.status(400).json({
        success: false,
        error: 'to, forRecipient and forSender (each a sealed-box envelope) are all required',
      });
    }
    if (!mongoose.isValidObjectId(to)) {
      return res.status(400).json({ success: false, error: 'Invalid recipient id' });
    }
    if (attachmentId && !mongoose.isValidObjectId(attachmentId)) {
      return res.status(400).json({ success: false, error: 'Invalid attachment id' });
    }
    if (await areUsersBlocked(req.user._id, to)) {
      return res.status(403).json({ success: false, error: 'Cannot message a blocked user' });
    }

    const expiresAt = resolveExpiresAt(expiresInSeconds);
    if (expiresAt === null) {
      return res.status(400).json({
        success: false,
        error: 'expiresInSeconds must be one of 30, 300, 3600, 86400, 604800',
      });
    }

const replyToId = await assertReplyAllowed(req, replyTo, { to });
   const replyToStoryId = await assertStoryReplyAllowed(replyToStory, req.user._id);
    const forwardMeta = await assertForwardAllowed(req, forwardedFrom); 
    const forwardPolicy = parseForwardPolicy(forwardPolicyRaw);

   const created = await Message.create({
      from: req.user._id,
      to,
      forRecipient: normalizeEnvelope(forRecipient),
      forSender: normalizeEnvelope(forSender),
      attachment: attachmentId || undefined,
      replyTo: replyToId,
      replyToStory: replyToStoryId,
      kind: kind === 'ai_note' ? 'ai_note' : 'text',
      expiresAt: expiresAt || undefined,
      forwardedFrom: forwardMeta,
      ...(forwardPolicy ? { forwardPolicy } : {}),
    });

    const message = await Message.findById(created._id)
      .populate('attachment', ATTACHMENT_POPULATE)
      .populate('replyTo', 'from forRecipient forSender envelopes group content createdAt');
    const payload = toClientMessage(message);

    const io = req.app.get('io');
    if (io) io.to(to.toString()).emit('message:new', payload);
    if (io) io.to(req.user._id.toString()).emit('message:new', payload);

    if (!isUserOnline(to)) {
      notifyUser(to, { title: 'QuantumChat', body: 'New message' }).catch(() => {});
    }

    incrementCiphertextsRelayed();
    res.status(201).json({ success: true, data: payload });
  } catch (err) {
    res.status(err.status || 500).json({ success: false, error: err.message });
  }
}

export async function publishQuantumAIDirectResponse(req, res) {
  try {
    const { content, contentHash, requestId, receipt, model } = req.body || {};
    if (
      !/^[0-9a-f]{64}$/i.test(contentHash || '') ||
      !/^[0-9a-f-]{36}$/i.test(requestId || '') ||
      typeof content !== 'string' ||
      !content.trim() ||
      content.length > 100_000
    ) {
      return res.status(400).json({ success: false, error: 'Invalid QuantumAI response payload' });
    }
    const ownKeys = (req.user.publicKeys || []).filter(Boolean);
    if (!ownKeys.length) return res.status(409).json({ success: false, error: 'No user encryption keys available' });
    const secret = process.env.QUANTUM_AI_SERVICE_SECRET;
    if (!secret || secret.length < 32) {
      return res.status(503).json({ success: false, error: 'QuantumAI service is not configured' });
    }
    const expected = crypto
      .createHmac('sha256', secret)
      .update(
        `${req.user._id}:peer:${req.user._id}:${String(contentHash).toLowerCase()}:${requestId}`
      )
      .digest();
    const received = Buffer.from(String(receipt || ''), 'hex');
    if (received.length !== expected.length || !crypto.timingSafeEqual(received, expected)) {
      return res.status(403).json({ success: false, error: 'Invalid QuantumAI service receipt' });
    }
    const actualHash = crypto.createHash('sha256').update(content, 'utf8').digest('hex');
    if (actualHash !== String(contentHash).toLowerCase()) {
      return res.status(403).json({ success: false, error: 'QuantumAI content hash mismatch' });
    }
    const quantumAI = await User.findOne({ systemRole: 'quantum_ai', isSystemUser: true });
    if (!quantumAI) return res.status(503).json({ success: false, error: 'QuantumAI identity is unavailable' });

    const created = await Message.create({
      from: quantumAI._id,
      to: req.user._id,
      forRecipient: sealForPublicKey(content, ownKeys[0]),
      forSender: sealForPublicKey(content, ownKeys[1] || ownKeys[0]),
      kind: 'ai',
      aiMetadata: {
        contentHash: String(contentHash).toLowerCase(),
        requestedBy: req.user._id,
        model: typeof model === 'string' ? model.slice(0, 120) : undefined,
        requestId,
      },
    });
    const payload = toClientMessage(created);
    const io = req.app.get('io');
    io?.to(String(req.user._id)).emit('message:new', payload);
    return res.status(201).json({ success: true, data: payload });
  } catch (err) {
    const status = err?.code === 11000 ? 409 : err.status || 500;
    return res.status(status).json({ success: false, error: status === 409 ? 'AI response already published' : err.message });
  }
}

export async function getConversation(req, res) {
  try {
    const { userId } = req.params;
    const peerOid = toObjectId(userId);
    if (!peerOid) {
      return res.status(400).json({ success: false, error: 'Invalid user id' });
    }

    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 80, 1), 200);
    const before = req.query.before ? new Date(req.query.before) : null;
    const markRead = req.query.markRead !== '0';

    const filter = {
      $and: [
        {
          $or: [
            { from: req.user._id, to: peerOid },
            { from: peerOid, to: req.user._id },
          ],
        },
        notExpiredFilter(),
      ],
    };
    if (before && !Number.isNaN(before.getTime())) {
      filter.$and.push({ createdAt: { $lt: before } });
    }

    const rows = await Message.find(filter)
      .sort({ createdAt: -1 })
      .limit(limit + 1)
      .populate('attachment', ATTACHMENT_POPULATE)
      .populate('replyTo', 'from forRecipient forSender envelopes group content createdAt');

    const hasMore = rows.length > limit;
    const page = hasMore ? rows.slice(0, limit) : rows;
    page.reverse();

    const now = new Date();
    const deliveredIds = [];
    const readIds = [];
    const allowReadReceipts = req.user.privacy?.readReceipts !== false;
    for (const msg of page) {
      if (String(msg.from) === String(userId) && String(msg.to) === String(req.user._id)) {
        if (!msg.deliveredAt) {
          msg.deliveredAt = now;
          deliveredIds.push(msg._id);
        }
        if (markRead && allowReadReceipts && !msg.readAt) {
          msg.readAt = now;
          msg.deliveredAt = msg.deliveredAt || now;
          readIds.push(msg._id);
        }
      }
    }
    if (deliveredIds.length || readIds.length) {
      const ops = [];
      if (deliveredIds.length) {
        ops.push(
          Message.updateMany(
            { _id: { $in: deliveredIds }, deliveredAt: null },
            { $set: { deliveredAt: now } }
          )
        );
      }
      if (readIds.length) {
        ops.push(
          Message.updateMany({ _id: { $in: readIds } }, { $set: { deliveredAt: now, readAt: now } })
        );
      }
      await Promise.all(ops);

      const io = req.app.get('io');
      if (io) {
        for (const msg of page) {
          if (
            String(msg.from) === String(userId) &&
            (deliveredIds.some((id) => String(id) === String(msg._id)) ||
              readIds.some((id) => String(id) === String(msg._id)))
          ) {
            const payload = {
              id: msg._id.toString(),
              deliveredAt: msg.deliveredAt,
              readAt: msg.readAt || null,
            };
            io.to(String(userId)).emit('message:status', payload);
          }
        }
      }
    }

    res.json({
      success: true,
      data: page.map(toClientMessage),
      meta: {
        hasMore,
        nextBefore: page.length ? page[0].createdAt : null,
      },
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

export async function markConversationRead(req, res) {
  try {
    const { userId } = req.params;
    if (!mongoose.isValidObjectId(userId)) {
      return res.status(400).json({ success: false, error: 'Invalid user id' });
    }
    const now = new Date();
    if (req.user.privacy?.readReceipts === false) {
      const delivered = await Message.updateMany(
        { from: userId, to: req.user._id, deliveredAt: null },
        { $set: { deliveredAt: now } }
      );
      return res.json({ success: true, data: { updated: delivered.modifiedCount, readReceipts: false } });
    }
    const result = await Message.updateMany(
      { from: userId, to: req.user._id, readAt: null },
      { $set: { deliveredAt: now, readAt: now } }
    );
    const io = req.app.get('io');
    if (io && result.modifiedCount > 0) {
      io.to(String(userId)).emit('message:status', {
        conversationWith: req.user._id.toString(),
        readAt: now,
        bulk: true,
      });
    }
    res.json({ success: true, data: { updated: result.modifiedCount } });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

export async function deleteMessage(req, res) {
  try {
    const { messageId } = req.params;
    if (!mongoose.isValidObjectId(messageId)) {
      return res.status(400).json({ success: false, error: 'Invalid message id' });
    }

    const message = await Message.findById(messageId);
    if (!message) return res.status(404).json({ success: false, error: 'Message not found' });

    const uid = req.user._id.toString();
    if (message.from.toString() !== uid) {
      return res.status(403).json({ success: false, error: 'Only the sender can delete this message for everyone' });
    }

    const payload = {
      id: message._id.toString(),
      from: message.from.toString(),
      to: message.to ? message.to.toString() : undefined,
      group: message.group ? message.group.toString() : undefined,
    };

    await removeAttachmentFiles(message.attachment);
    await Message.deleteOne({ _id: message._id });

    const io = req.app.get('io');
    if (message.group) {
      const Group = (await import('../models/Group.js')).default;
      const group = await Group.findById(message.group);
      if (group && io) {
        for (const memberId of group.members) {
          io.to(memberId.toString()).emit('message:deleted', payload);
        }
      }
    } else {
      emitToParticipants(io, message, 'message:deleted', payload);
    }

    res.json({ success: true, data: payload });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

export async function reactToMessage(req, res) {
  try {
    const { messageId } = req.params;
    const { forRecipient, forSender, clear } = req.body;
    if (!mongoose.isValidObjectId(messageId)) {
      return res.status(400).json({ success: false, error: 'Invalid message id' });
    }

    const message = await Message.findById(messageId);
    if (!message) return res.status(404).json({ success: false, error: 'Message not found' });

    const uid = req.user._id.toString();
    let isParty = false;
    let groupMemberIds = null;
    if (message.group) {
      const Group = (await import('../models/Group.js')).default;
      const group = await Group.findById(message.group);
      if (!group) return res.status(404).json({ success: false, error: 'Group not found' });
      groupMemberIds = group.members.map((m) => m.toString());
      isParty = groupMemberIds.includes(uid);
    } else if (message.to) {
      isParty = [message.from.toString(), message.to.toString()].includes(uid);
    }
    if (!isParty) return res.status(403).json({ success: false, error: 'Not authorized' });

    if (clear) {
      message.reactions = message.reactions.filter((r) => r.user.toString() !== uid);
    } else {
      if (!validateEnvelope(forRecipient) || !validateEnvelope(forSender)) {
        return res.status(400).json({
          success: false,
          error: 'forRecipient and forSender sealed-box envelopes are required',
        });
      }
      const nextReaction = {
        user: req.user._id,
        forRecipient: normalizeEnvelope(forRecipient),
        forSender: normalizeEnvelope(forSender),
        createdAt: new Date(),
      };
      const idx = message.reactions.findIndex((r) => r.user.toString() === uid);
      if (idx >= 0) message.reactions[idx] = nextReaction;
      else message.reactions.push(nextReaction);
      message.markModified('reactions');
    }

    await message.save();
    const populated = await Message.findById(message._id)
      .populate('attachment', ATTACHMENT_POPULATE)
      .populate('replyTo', 'from forRecipient forSender envelopes group content createdAt');
    const payload = toClientMessage(populated);

    const io = req.app.get('io');
    if (groupMemberIds) {
      for (const memberId of groupMemberIds) io?.to(memberId).emit('message:reaction', payload);
    } else {
      emitToParticipants(io, message, 'message:reaction', payload);
    }

    res.json({ success: true, data: payload });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

export async function editMessage(req, res) {
  try {
    const { messageId } = req.params;
    const { forRecipient, forSender, envelopes } = req.body;
    if (!mongoose.isValidObjectId(messageId)) {
      return res.status(400).json({ success: false, error: 'Invalid message id' });
    }

    const message = await Message.findById(messageId);
    if (!message) return res.status(404).json({ success: false, error: 'Message not found' });
    if (message.from.toString() !== req.user._id.toString()) {
      return res.status(403).json({ success: false, error: 'Only the sender can edit this message' });
    }

    if (message.group) {
      const Group = (await import('../models/Group.js')).default;
      const group = await Group.findById(message.group);
      const isPublic = group?.visibility === 'public';
      if (isPublic) {
        const { content: contentRaw } = req.body;
        if (typeof contentRaw !== 'string' || !contentRaw.trim()) {
          return res.status(400).json({
            success: false,
            error: 'Public group edit requires non-empty content',
          });
        }
        message.content = contentRaw.trim().slice(0, 8000);
        message.envelopes = undefined;
        message.markModified('content');
      } else {
        if (!Array.isArray(envelopes) || envelopes.length < 2) {
          return res.status(400).json({ success: false, error: 'Group edit requires envelopes for each member' });
        }
        message.envelopes = envelopes.map((item) => ({
          user: item.user,
          ...normalizeEnvelope(item),
        }));
        message.content = undefined;
        message.markModified('envelopes');
      }
    } else {
      if (!validateEnvelope(forRecipient) || !validateEnvelope(forSender)) {
        return res.status(400).json({
          success: false,
          error: 'forRecipient and forSender sealed-box envelopes are required',
        });
      }
      message.forRecipient = normalizeEnvelope(forRecipient);
      message.forSender = normalizeEnvelope(forSender);
    }

    message.editedAt = new Date();
    await message.save();

    const populated = await Message.findById(message._id)
      .populate('attachment', ATTACHMENT_POPULATE)
      .populate('replyTo', 'from forRecipient forSender envelopes group content createdAt');
    const payload = toClientMessage(populated);

    const io = req.app.get('io');
    if (message.group) {
      const Group = (await import('../models/Group.js')).default;
      const group = await Group.findById(message.group);
      if (group && io) {
        for (const memberId of group.members) {
          io.to(memberId.toString()).emit('message:edited', payload);
        }
      }
    } else {
      emitToParticipants(io, message, 'message:edited', payload);
    }

    res.json({ success: true, data: payload });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}
