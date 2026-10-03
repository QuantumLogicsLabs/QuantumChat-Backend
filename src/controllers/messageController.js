import crypto from 'crypto';
import mongoose from 'mongoose';
import { getStorage } from '../middleware/upload.js';
import Attachment from '../models/Attachment.js';
import Group from '../models/Group.js';
import Message from '../models/Message.js';
import User from '../models/User.js';
import { incrementCiphertextsRelayed } from '../services/blindnessStats.js';
import { notifyUser } from '../services/pushService.js';
import { conversationKey, parseConversationKey } from '../utils/conversationKey.js';
import { notExpiredFilter, resolveExpiresAt } from '../utils/messageExpiry.js';
import { sealForPublicKey } from '../utils/sealedBox.js';
import {
  getDirectTranscriptTargetKey,
  isDirectTranscriptTargetAllowed,
} from '../utils/transcriptionAccess.js';
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

function allowsReadReceipts(privacy) {
  const value = privacy?.readReceipts;
  if (value === false || value === 'nobody') return false;
  return true;
}
async function assertCanDirectMessageWithDoc(senderId, recipient) {
  const senderOid = toObjectId(senderId);
  const recipientOid = recipient._id;
  if (!senderOid) {
    const err = new Error('Invalid recipient id');
    err.status = 400;
    throw err;
  }
  if (String(senderOid) === String(recipientOid)) return;
  const policy = recipient.privacy?.whoCanMessage || 'everyone';
  if (policy === 'everyone') return;

  const recipientFriends = (recipient.friends || []).map(String);
  const senderIsFriend = recipientFriends.includes(String(senderOid));
 if (policy === 'friends') {
    if (!senderIsFriend) {
      const err = new Error('This user is not accepting messages from friends');
      err.status = 403;
      err.code = 'NOT_FRIENDS';
      err.recipientId = String(recipientOid);
      err.recipientUsername = recipient.username;
      throw err;
    }
    return;
  }
  if (policy === 'friendsOfFriends') {
    if (senderIsFriend) return;
    const sender = await User.findById(senderOid).select('friends');
    const senderFriends = new Set((sender?.friends || []).map(String));
    const mutual = recipientFriends.some((id) => senderFriends.has(id));
  if (!mutual) {
      const err = new Error('This user is not accepting messages from friends of friends');
      err.status = 403;
      err.code = 'NOT_FRIENDS';
      err.recipientId = String(recipientOid);
      err.recipientUsername = recipient.username;
      throw err;
    }
  }
}

function mediaKindFromAttachment(attachment) {
  if (!attachment) return null;
  const mime = String(attachment.mimetype || '').toLowerCase();
  const name = String(attachment.filename || '').toLowerCase();
  if (mime.startsWith('video/')) return 'video';
  if (mime.startsWith('audio/') || /^voice-note/i.test(name)) {
    return 'audio';
  }
  if (mime.startsWith('image/') || /\.(png|jpe?g|gif|webp|bmp)$/i.test(name)) return 'image';
  if (/\.(mp4|webm|mov|mkv|avi)$/i.test(name)) return 'video';
  if (/\.(ogg|mp3|m4a|wav|aac)$/i.test(name)) return 'audio';
  return null;
}

function viewOnceAllowedForAttachment(attachment) {
  return Boolean(mediaKindFromAttachment(attachment));
}

// Maps an attachment to the "Clear chat" category bucket. Any attachment
// that isn't image/video/audio falls into 'document' (pdf, zip, etc.).
function attachmentCategory(attachment) {
  if (!attachment) return undefined;
  const kind = mediaKindFromAttachment(attachment);
  if (kind === 'image') return 'photo';
  if (kind === 'video') return 'video';
  if (kind === 'audio') return 'voice';
  return 'document';
}

// Builds the Mongo condition that matches messages hidden by one scoped
// clear entry: everything at/before clearedAt, narrowed to the entry's
// media category (or, for 'text', messages with no attachment at all).
// 'all' hides everything regardless of category, same as the original
// single-watermark behavior.
function scopeCreatedAtCondition(scope, clearedAt) {
  const base = { createdAt: { $lte: clearedAt } };
  if (scope === 'all') return base;
  if (scope === 'text') {
    // Plain text only — must not treat legacy media (no mediaCategory field)
    // as text, or a "Text messages" clear would wipe the whole chat.
    return {
      ...base,
      $and: [
        { $or: [{ attachment: { $exists: false } }, { attachment: null }] },
        { $or: [{ mediaCategory: { $exists: false } }, { mediaCategory: null }] },
      ],
    };
  }
  return { ...base, mediaCategory: scope };
}
export function toClientMessage(doc, viewerId) {
  const message = typeof doc.toObject === 'function' ? doc.toObject() : { ...doc };
  message.id = message._id;
  if (message.attachment && typeof message.attachment === 'object') {
    message.attachment = {
      ...message.attachment,
      id: message.attachment._id || message.attachment.id,
    };
  }
  if (message.group) message.group = message.group._id || message.group;
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
  if (Array.isArray(message.editHistory)) {
    message.editHistory = message.editHistory.map((h) => ({
      forRecipient: h.forRecipient,
      forSender: h.forSender,
      content: h.content,
      envelopes: Array.isArray(h.envelopes)
        ? h.envelopes.map((e) => ({ ...e, user: e.user?.toString?.() || String(e.user) }))
        : undefined,
      editedAt: h.editedAt,
    }));
  }
  if (Array.isArray(message.deliveredTo)) {
    message.deliveredTo = message.deliveredTo.map((d) => ({
      user: d.user?.toString?.() || String(d.user),
      at: d.at,
    }));
  }
  if (Array.isArray(message.readBy)) {
    message.readBy = message.readBy.map((r) => ({
      user: r.user?.toString?.() || String(r.user),
      at: r.at,
    }));
  }
  if (message.viewOnceOpenedBy) {
    message.viewOnceOpenedBy = message.viewOnceOpenedBy?.toString?.() || String(message.viewOnceOpenedBy);
  }
  // Never leak ciphertext metadata after a view-once open.
  if (message.viewOnce && message.viewOnceOpenedAt) {
    message.attachment = null;
  }
  if (message.timeCapsule && message.unlocksAt && new Date(message.unlocksAt) > new Date()) {
    const isSender = viewerId && String(message.from) === String(viewerId);
    if (!isSender) {
      message.forRecipient = undefined;
      message.forSender = undefined;
      message.attachment = null;
      message.locked = true;
    }
  }
  if (message.transcription) {
    const entries = Array.isArray(message.transcription.entries)
      ? message.transcription.entries
      : [];
    message.transcription = {
      ...message.transcription,
      claimToken: undefined,
      claimLeaseUntil: undefined,
      claimedBy: undefined,
      entries: entries
        .filter((entry) => Boolean(viewerId) && String(entry.user) === String(viewerId))
        .map((entry) => ({
          ...entry,
          user: entry.user?.toString?.() || String(entry.user),
          claimToken: undefined,
          claimLeaseUntil: undefined,
        })),
    };
  }
  return message;
}

function isMessageHiddenByClear(message, user) {
  const key = message.group
    ? `group:${String(message.group)}`
    : conversationKey({ from: message.from, to: message.to });
  const createdAt = new Date(message.createdAt).getTime();
  const attachmentCategoryValue = message.mediaCategory || attachmentCategory(message.attachment);
  return (user.clearedConversations || []).some((entry) => {
    if (entry.conversationKey !== key || !entry.clearedAt) return false;
    if (createdAt > new Date(entry.clearedAt).getTime()) return false;
    const scope = entry.scope || 'all';
    if (scope === 'all') return true;
    if (scope === 'text') return !attachmentCategoryValue;
    return attachmentCategoryValue === scope;
  });
}

async function findMessageForUser(messageId, userId) {
  const message = await Message.findById(messageId).populate('attachment', ATTACHMENT_POPULATE);
  if (!message) return null;
  const uid = String(userId);
  if (!message.group) {
    return [String(message.from), String(message.to)] .includes(uid) ? message : null;
  }
  const group = await Group.findById(message.group).select('members');
  return group?.members?.some((memberId) => String(memberId) === uid) ? message : null;
}

export async function getImportantMessages(req, res) {
  try {
    const user = await User.findById(req.user._id).select('importantMessages clearedConversations');
    const references = Array.isArray(user?.importantMessages) ? user.importantMessages : [];
    const ids = references
      .map((entry) => entry.messageId)
      .filter((id) => mongoose.isValidObjectId(id));
    if (!ids.length) return res.json({ success: true, data: { messages: [], entries: [] } });

    const rows = await Message.find({ _id: { $in: ids }, ...notExpiredFilter() })
      .populate('attachment', ATTACHMENT_POPULATE)
      .sort({ createdAt: -1 });
    const groupIds = [...new Set(rows.filter((message) => message.group).map((message) => String(message.group)))];
    const groups = groupIds.length
      ? await Group.find({ _id: { $in: groupIds }, members: req.user._id }).select('_id name')
      : [];
    const allowedGroups = new Map(groups.map((group) => [String(group._id), group]));
    const allowed = rows.filter((message) => {
      const direct = !message.group && [String(message.from), String(message.to)].includes(String(req.user._id));
      const groupAllowed = message.group && allowedGroups.has(String(message.group));
      return (direct || groupAllowed) && !isMessageHiddenByClear(message, user);
    });
    const allowedIds = new Set(allowed.map((message) => String(message._id)));
    const validReferences = references.filter((entry) => allowedIds.has(String(entry.messageId)));
    if (validReferences.length !== references.length) {
      user.importantMessages = validReferences;
      await user.save();
    }

    res.json({
      success: true,
      data: {
        messages: allowed.map((message) => toClientMessage(message, req.user._id)),
        entries: validReferences.map((entry) => ({ messageId: String(entry.messageId), markedAt: entry.markedAt })),
      },
    });
  } catch (err) {
    res.status(err.status || 500).json({ success: false, error: err.message });
  }
}

export async function markMessageImportant(req, res) {
  try {
    const { messageId } = req.params;
    if (!mongoose.isValidObjectId(messageId)) {
      return res.status(400).json({ success: false, error: 'Invalid message id' });
    }
    const message = await findMessageForUser(messageId, req.user._id);
    if (!message) return res.status(404).json({ success: false, error: 'Message not found' });
    if (isMessageHiddenByClear(message, req.user)) {
      return res.status(404).json({ success: false, error: 'Message is no longer available' });
    }
    const user = await User.findById(req.user._id).select('importantMessages');
    const references = Array.isArray(user.importantMessages) ? user.importantMessages : [];
    if (!references.some((entry) => String(entry.messageId) === messageId)) {
      user.importantMessages = [{ messageId, markedAt: new Date() }, ...references];
      await user.save();
    }
    res.json({ success: true, data: { messageId, important: true } });
  } catch (err) {
    res.status(err.status || 500).json({ success: false, error: err.message });
  }
}

export async function unmarkMessageImportant(req, res) {
  try {
    const { messageId } = req.params;
    if (!mongoose.isValidObjectId(messageId)) {
      return res.status(400).json({ success: false, error: 'Invalid message id' });
    }
    const user = await User.findById(req.user._id).select('importantMessages');
    user.importantMessages = (user.importantMessages || [])
      .filter((entry) => String(entry.messageId) !== messageId);
    await user.save();
    res.json({ success: true, data: { messageId, important: false } });
  } catch (err) {
    res.status(err.status || 500).json({ success: false, error: err.message });
  }
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
  const storage = getStorage();
  try {
    await storage.delete(attachment.storagePath);
    if (attachment.forSenderStoragePath) {
      await storage.delete(attachment.forSenderStoragePath);
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
  if (original.viewOnce) {
    const err = new Error('View once media cannot be forwarded');
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
    if (original.viewOnce) {
      return res.json({
        success: true,
        data: { allowed: false, reason: 'View once media cannot be forwarded' },
      });
    }
    const verdict = evaluateForwardPolicy(original);
    return res.json({ success: true, data: verdict });
  } catch (err) {
    res.status(err.status || 500).json({ success: false, error: err.message });
  }
}

export async function upsertTranscriptState(req, res) {
  try {
    const { messageId } = req.params;
    const messageOid = toObjectId(messageId);
    if (!messageOid) {
      return res.status(400).json({ success: false, error: 'Invalid message id' });
    }
    const message = await Message.findById(messageOid);
    if (!message) return res.status(404).json({ success: false, error: 'Message not found' });
    const userId = String(req.user._id);
    const expectedTargetPublicKey = getDirectTranscriptTargetKey(message, userId);
    if (!expectedTargetPublicKey) {
      return res.status(403).json({ success: false, error: 'Only direct-message participants can manage transcript state' });
    }
    if (message.viewOnce) {
      return res.status(403).json({ success: false, error: 'View-once voice messages cannot be transcribed' });
    }

    const { action = 'claim', claimToken, status, language, encryptedText, nonce, ephemeralPublicKey, targetPublicKey, error } = req.body || {};
    const transcription = message.transcription || {};
    const entries = transcription.entries || [];
    if (!transcription.entries) transcription.entries = entries;
    let participant = entries.find((entry) => String(entry.user) === userId);

    const participantPayload = (entry, includeClaimToken = false) => {
      const payload = entry?.toObject ? entry.toObject() : { ...entry };
      payload.user = String(payload.user);
      if (!includeClaimToken) {
        delete payload.claimToken;
        delete payload.claimLeaseUntil;
      }
      return payload;
    };

    if (action === 'claim') {
      if (participant?.status === 'completed' && participant.encryptedText) {
        return res.json({
          success: true,
          data: { transcription: { participant: participantPayload(participant) } },
        });
      }
      if (participant?.claimLeaseUntil && new Date(participant.claimLeaseUntil).getTime() > Date.now()) {
        return res.status(409).json({ success: false, error: 'Transcript is already being generated for this participant' });
      }

      const token = crypto.randomBytes(16).toString('hex');
      const lease = new Date(Date.now() + 60_000);
      if (!participant) {
        transcription.entries.push({
          user: req.user._id,
          status: 'running',
          model: transcription.model || 'Xenova/whisper-tiny',
          revision: transcription.revision || '5332fcc35e32a33b86612b9a57a89be7906102b1',
          claimToken: token,
          claimLeaseUntil: lease,
          language: typeof language === 'string' ? language.slice(0, 32) : undefined,
          createdAt: new Date(),
          updatedAt: new Date(),
        });
        participant = transcription.entries[transcription.entries.length - 1];
      } else {
        participant.status = 'running';
        participant.claimToken = token;
        participant.claimLeaseUntil = lease;
        participant.language = typeof language === 'string' ? language.slice(0, 32) : participant.language;
        participant.error = undefined;
        participant.updatedAt = new Date();
      }
      message.transcription = transcription;
      await message.save();
      return res.json({
        success: true,
        data: { transcription: { participant: participantPayload(participant, true) } },
      });
    }

    if (action === 'release') {
      if (!participant || !claimToken || String(claimToken) !== String(participant.claimToken || '')) {
        return res.status(409).json({ success: false, error: 'Transcript claim token is invalid or expired' });
      }
      participant.status = 'failed';
      participant.claimToken = undefined;
      participant.claimLeaseUntil = null;
      participant.error = typeof error === 'string' && error.trim() ? error.slice(0, 500) : undefined;
      participant.updatedAt = new Date();
      message.transcription = transcription;
      await message.save();
      return res.json({
        success: true,
        data: { transcription: { participant: participantPayload(participant) } },
      });
    }

    if (action === 'commit') {
      if (!participant || !claimToken || String(claimToken) !== String(participant.claimToken || '')) {
        return res.status(409).json({ success: false, error: 'Transcript claim token is invalid or expired' });
      }
      if (!participant.claimLeaseUntil || new Date(participant.claimLeaseUntil).getTime() < Date.now()) {
        return res.status(409).json({ success: false, error: 'Transcript claim has expired' });
      }
      if (!encryptedText || !nonce || !ephemeralPublicKey || !targetPublicKey) {
        return res.status(400).json({ success: false, error: 'Transcript ciphertext and envelope metadata are required' });
      }
      if (
        !HEX_64.test(ephemeralPublicKey) ||
        !isDirectTranscriptTargetAllowed(message, userId, targetPublicKey)
      ) {
        return res.status(403).json({ success: false, error: 'Transcript envelope must target the authenticated participant' });
      }

      participant.status = typeof status === 'string' ? status : 'completed';
      participant.language = typeof language === 'string' ? language.slice(0, 32) : participant.language;
      participant.claimToken = undefined;
      participant.claimLeaseUntil = null;
      participant.encryptedText = String(encryptedText);
      participant.nonce = String(nonce);
      participant.ephemeralPublicKey = String(ephemeralPublicKey).toLowerCase();
      participant.targetPublicKey = String(targetPublicKey).toLowerCase();
      participant.error = typeof error === 'string' && error.trim() ? error.slice(0, 500) : undefined;
      participant.updatedAt = new Date();
      transcription.model = transcription.model || 'Xenova/whisper-tiny';
      transcription.revision = transcription.revision || '5332fcc35e32a33b86612b9a57a89be7906102b1';
      message.transcription = transcription;
      await message.save();
      return res.json({
        success: true,
        data: { transcription: { participant: participantPayload(participant) } },
      });
    }

    return res.status(400).json({ success: false, error: 'Unsupported transcript action' });
  } catch (err) {
    res.status(err.status || 500).json({ success: false, error: err.message });
  }
}

export async function sendMessage(req, res) {
  try {
    const {
      to,
      clientMessageId,
      forRecipient,
      forSender,
      attachmentId,
      replyTo,
      forwardedFrom,
      kind,
      expiresInSeconds,
      forwardPolicy: forwardPolicyRaw,
      viewOnce: viewOnceRaw,
      timeCapsule: timeCapsuleRaw,
      unlocksAt: unlocksAtRaw,
    } = req.body;
   if (!to || !validateEnvelope(forRecipient) || !validateEnvelope(forSender)) {
      return res.status(400).json({
        success: false,
        error: 'to, forRecipient and forSender (each a sealed-box envelope) are all required',
      });
    }
    const cleanClientMessageId =
      typeof clientMessageId === 'string' && /^[a-zA-Z0-9_-]{8,100}$/.test(clientMessageId.trim())
        ? clientMessageId.trim()
        : null;
    if (clientMessageId != null && !cleanClientMessageId) {
      return res.status(400).json({ success: false, error: 'Invalid client message id' });
    }
    if (cleanClientMessageId) {
      const existing = await Message.findOne({ from: req.user._id, clientMessageId: cleanClientMessageId });
      if (existing) {
        return res.status(200).json({ success: true, data: toClientMessage(existing) });
      }
    }
    const toOid = toObjectId(to);
    if (!toOid) {
      return res.status(400).json({ success: false, error: 'Invalid recipient id' });
    }
    if (attachmentId && !mongoose.isValidObjectId(attachmentId)) {
      return res.status(400).json({ success: false, error: 'Invalid attachment id' });
    }
    const recipient = await User.findById(toOid).select('privacy friends blockedUsers username');
    if (!recipient) {
      return res.status(404).json({ success: false, error: 'Recipient not found' });
    }
    const senderBlockedRecipient = (req.user.blockedUsers || []).some((id) => String(id) === String(toOid));
    const recipientBlockedSender = (recipient.blockedUsers || []).some((id) => String(id) === String(req.user._id));
    if (senderBlockedRecipient || recipientBlockedSender) {
      return res.status(403).json({ success: false, error: 'Cannot message a blocked user' });
    }
    if (req.user.moderation?.status === 'restricted') {
      const isFriend = (req.user.friends || []).some((id) => String(id) === String(toOid));
      const isSelfChat = String(toOid) === String(req.user._id);
      if (!isFriend && !isSelfChat) {
        return res.status(403).json({
          success: false,
          error: 'Your account is currently restricted from messaging new contacts',
        });
      }
    }
    await assertCanDirectMessageWithDoc(req.user._id, recipient);
    const expiresAt = resolveExpiresAt(expiresInSeconds);
    if (expiresAt === null) {
      return res.status(400).json({
        success: false,
        error: 'expiresInSeconds must be one of 30, 300, 3600, 86400, 604800',
      });
    }

        let isCapsule = false;
    let unlocksAt;
    if (timeCapsuleRaw === true || timeCapsuleRaw === 'true') {
      isCapsule = true;
      unlocksAt = new Date(unlocksAtRaw);
      if (!unlocksAtRaw || Number.isNaN(unlocksAt.getTime()) || unlocksAt.getTime() <= Date.now()) {
        return res.status(400).json({
          success: false,
          error: 'unlocksAt must be a valid future date for a time capsule message',
        });
      }
    }

    const replyToId = await assertReplyAllowed(req, replyTo, { to: toOid });
    const forwardMeta = await assertForwardAllowed(req, forwardedFrom);
    const forwardPolicy = parseForwardPolicy(forwardPolicyRaw);
    let attachmentDoc = null;
    if (attachmentId) {
      attachmentDoc = await Attachment.findById(toObjectId(attachmentId)).select('mimetype filename');
    }
    const mediaCategory = attachmentCategory(attachmentDoc);

    let viewOnce = viewOnceRaw === true;
    let viewOnceMediaKind = null;
    if (viewOnce) {
      if (!attachmentDoc || !viewOnceAllowedForAttachment(attachmentDoc)) {
        return res.status(400).json({
          success: false,
          error: 'View once is only available for photo, video, or voice attachments',
        });
      }
      viewOnceMediaKind = mediaKindFromAttachment(attachmentDoc);
    }

    // Vault decoy: if I have this recipient vaulted and my vault is
    // currently locked on this request, this message belongs to the decoy
    // thread only — it will never appear once I unlock the real vault view,
    // and the real (pre-vaulting) history stays completely untouched.
    const senderVaultedPeers = (req.user.vaultedPeers || []).map((v) => String(v.peer));
    const isDecoySend = senderVaultedPeers.includes(String(toOid)) && !req.vaultUnlocked;

    const created = await Message.create({
      from: req.user._id,
      clientMessageId: clientMessageId || undefined,
      to: toOid,
      forRecipient: normalizeEnvelope(forRecipient),
      forSender: normalizeEnvelope(forSender),
      attachment: attachmentId || undefined,
      mediaCategory,
      replyTo: replyToId,
      kind: kind === 'ai_note' ? 'ai_note' : 'text',
      expiresAt: expiresAt || undefined,
      timeCapsule: isCapsule || undefined,
      unlocksAt: isCapsule ? unlocksAt : undefined,
      forwardedFrom: forwardMeta,
      decoyFor: isDecoySend ? req.user._id : undefined,
      ...(forwardPolicy ? { forwardPolicy } : {}),
      ...(viewOnce
        ? {
            viewOnce: true,
            viewOnceMediaKind,
            forwardPolicy: { allowForward: false, forwardUntil: null },
          }
        : {}),
    });

    // Skip a second round-trip when nothing needs populate — text sends are the hot path.
    let message = created;
    if (attachmentId || replyToId) {
      message = await Message.findById(created._id)
        .populate('attachment', ATTACHMENT_POPULATE)
        .populate('replyTo', 'from forRecipient forSender envelopes group content createdAt');
    }
    const payload = toClientMessage(message);
    const isSelfChat = String(toOid) === String(req.user._id);

    const io = req.app.get('io');
    if (io) {
      // Time capsules: only echo to the sender's own devices right now.
      // The recipient gets nothing over the socket — not even a redacted
      // placeholder — until jobs/timeCapsuleDelivery.js unlocks it. They'll
      // see the locked placeholder next time they fetch the conversation.
      if (!isCapsule) {
        io.to(toOid.toString()).emit('message:new', payload);
      }
      if (!isSelfChat) {
        io.to(req.user._id.toString()).emit('message:new', payload);
      }
    }

    if (!isSelfChat && !isCapsule) {
      notifyUser(toOid, {
        title: 'QuantumChat',
        body: 'New message',
        kind: 'dm',
        conversationKey: conversationKey({ from: req.user._id, to: toOid }),
        url: `/chat/${req.user._id}`,
        actions: [
          { action: 'reply', title: 'Reply', type: 'text', placeholder: 'Type a reply…' },
          { action: 'mark_read', title: 'Mark as Read' },
        ],
        data: { fromUserId: String(req.user._id) },
      }).catch(() => { });
    }

    incrementCiphertextsRelayed();
    res.status(201).json({ success: true, data: payload });
  } catch (err) {
    res.status(err.status || 500).json({
      success: false,
      error: err.message,
      code: err.code || undefined,
      recipientId: err.recipientId || undefined,
    });
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

/** Path segments registered as static message routes — never treat as peer ids. */
const RESERVED_MESSAGE_PEER_IDS = new Set([
  'important',
  'sync',
  'quantum-ai-response',
]);

export async function getConversation(req, res) {
  try {
    const { userId } = req.params;
    if (RESERVED_MESSAGE_PEER_IDS.has(String(userId || '').toLowerCase())) {
      return res.status(404).json({ success: false, error: 'Not found' });
    }
    const peerOid = toObjectId(userId);
    if (!peerOid) {
      return res.status(400).json({ success: false, error: 'Invalid user id' });
    }

    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 80, 1), 200);
    const before = req.query.before ? new Date(req.query.before) : null;
    const markRead = req.query.markRead !== '0';

    const myVaultedPeers = (req.user.vaultedPeers || []).map((v) => String(v.peer));
    const isVaultedConversation = myVaultedPeers.includes(String(peerOid));

    const filter = {
      $and: [
        {
          $or: [
            { from: req.user._id, to: peerOid },
            { from: peerOid, to: req.user._id },
          ],
        },
        notExpiredFilter(),
        // Vault separation only applies to conversations I've vaulted.
        // Locked: show only my decoy thread for this peer (a genuinely
        // separate, initially-empty history). Unlocked or not vaulted:
        // show only real messages, decoys never leak through.
        isVaultedConversation && !req.vaultUnlocked
          ? { decoyFor: req.user._id }
          : { decoyFor: null },
      ],
    };
    if (before && !Number.isNaN(before.getTime())) {
      filter.$and.push({ createdAt: { $lt: before } });
    }

    // "Clear chat" watermarks: hide messages this user cleared, scoped by
    // media category (or all). Per-user only — the peer's view is untouched,
    // and new messages after each scope's clear moment still appear normally.
    const dmKey = conversationKey({ from: req.user._id, to: peerOid });
    const dmClearExclusions = (req.user.clearedConversations || [])
      .filter((c) => c.conversationKey === dmKey && c.clearedAt)
      .map((c) => scopeCreatedAtCondition(c.scope || 'all', new Date(c.clearedAt)));
    if (dmClearExclusions.length) {
      filter.$and.push({ $nor: dmClearExclusions });
    }

    const rows = await Message.find(filter)
      .sort({ createdAt: -1 })
      .limit(limit + 1)
      .populate('attachment', ATTACHMENT_POPULATE)
      .populate('replyTo', 'from forRecipient forSender envelopes group content createdAt')
      .lean();
    const hasMore = rows.length > limit;
    const page = hasMore ? rows.slice(0, limit) : rows;
    page.reverse();

    const now = new Date();
    const deliveredIds = [];
    const readIds = [];
    const allowReadReceipts = allowsReadReceipts(req.user.privacy);
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
      data: page.map((m) => toClientMessage(m, req.user._id)),
      meta: {
        hasMore,
        nextBefore: page.length ? page[0].createdAt : null,
      },
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

// Realtime sync polling. The Vercel serverless deployment cannot hold a
// WebSocket, so clients poll this instead of receiving socket 'message:new'.
// It returns the identical toClientMessage() payload the socket emits — sealed
// X5 envelopes only, no plaintext, no key material.
const SYNC_FLOOR_MS = 24 * 60 * 60 * 1000; // cap lookback; never scan full history
const SYNC_LIMIT = 200;
const SYNC_OVERLAP_MS = 5000; // re-send window; the client dedupes by message id

/**
 * Returns every message across all of the caller's DMs and groups created after
 * `since`. Deliberately a pure read — no read receipts are written here, because
 * this spans conversations the user may not even have open.
 */
export async function syncMessages(req, res) {
  try {
    const requested = req.query.since ? new Date(req.query.since) : null;
    const now = Date.now();
    const floor = now - SYNC_FLOOR_MS;
    // Clamp into [now - 24h, now]. The lower bound stops full-history scans; the
    // upper bound matters because the cursor round-trips through the client — a
    // device with a fast clock would otherwise ask for a future timestamp and
    // silently skip every message written in the meantime.
    const since =
      requested && !Number.isNaN(requested.getTime())
        ? new Date(Math.min(Math.max(requested.getTime(), floor), now))
        : new Date(floor);

    const groupIds = await Group.find({ members: req.user._id }).distinct('_id');

    // Vault unlock is a single flag for the whole request, not per-peer — the
    // JWT doesn't enumerate peers. So: locked -> vaulted peers show decoy-only,
    // everything else (unvaulted DMs + groups) shows real-only. Unlocked ->
    // real-only for everyone; decoys never leak into the unlocked view, same
    // rule as getConversation.
    const vaultedPeerIds = req.vaultUnlocked
      ? []
      : (req.user.vaultedPeers || [])
        .map((v) => toObjectId(v.peer))
        .filter(Boolean);

    const involvesVaultedPeer = vaultedPeerIds.length
      ? [
        { from: req.user._id, to: { $in: vaultedPeerIds } },
        { from: { $in: vaultedPeerIds }, to: req.user._id },
      ]
      : null;

    const scopeFilter = involvesVaultedPeer
      ? {
        $or: [
          // Locked + vaulted peer: decoy thread only.
          {
            $and: [{ decoyFor: req.user._id }, { $or: involvesVaultedPeer }],
          },
          // Everything else: real messages only, decoys never leak.
          { decoyFor: null, $nor: involvesVaultedPeer },
        ],
      }
      : { decoyFor: null };

    // "Clear chat" watermarks. For each conversation this user has cleared,
    // exclude messages created at or before the clear moment. Sync spans all of
    // the caller's conversations, so this is a $nor of per-conversation
    // (scope + createdAt<=clearedAt) clauses. Cleared messages never resurface
    // through sync on any of the user's devices; newer messages are unaffected.
    const myId = req.user._id;
    const clearExclusions = [];
    for (const entry of req.user.clearedConversations || []) {
      const clearedAt = entry && entry.clearedAt ? new Date(entry.clearedAt) : null;
      if (!clearedAt) continue;
      const parts = parseConversationKey(entry.conversationKey);
      if (!parts) continue;
      const scopeCond = scopeCreatedAtCondition(entry.scope || 'all', clearedAt);
      if (parts.group) {
        const gid = toObjectId(parts.group);
        if (gid) clearExclusions.push({ group: gid, ...scopeCond });
      } else if (parts.dm) {
        const peerRaw = parts.dm.find((id) => String(id) !== String(myId)) || parts.dm[0];
        const peerOid = toObjectId(peerRaw);
        if (peerOid) {
          clearExclusions.push({
            $or: [
              { from: myId, to: peerOid },
              { from: peerOid, to: myId },
            ],
            ...scopeCond,
          });
        }
      }
    }

    const filter = {
      $and: [
        {
          $or: [
            { to: req.user._id },
            { from: req.user._id },
            { group: { $in: groupIds } },
          ],
        },
        { createdAt: { $gt: since } },
        notExpiredFilter(),
        scopeFilter,
        ...(clearExclusions.length ? [{ $nor: clearExclusions }] : []),
      ],
    };

    const rows = await Message.find(filter)
      .sort({ createdAt: 1 })
      .limit(SYNC_LIMIT + 1)
      .populate('attachment', ATTACHMENT_POPULATE)
      .populate('replyTo', 'from forRecipient forSender envelopes group content createdAt');

    const hasMore = rows.length > SYNC_LIMIT;
    const page = hasMore ? rows.slice(0, SYNC_LIMIT) : rows;

    res.json({
      success: true,
      data: page.map(toClientMessage),
      meta: {
        hasMore,
        // Server-issued cursor, rolled back by an overlap window. Client clocks
        // are not trusted, and the last row's createdAt would be lossy: a write
        // landing in the same millisecond but committing after this query would
        // never be seen again. Overlap + client-side dedupe is lossless.
        cursor: new Date(Date.now() - SYNC_OVERLAP_MS).toISOString(),
      },
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

export async function markConversationRead(req, res) {
  try {
    const { userId } = req.params;
    if (RESERVED_MESSAGE_PEER_IDS.has(String(userId || '').toLowerCase())) {
      return res.status(404).json({ success: false, error: 'Not found' });
    }
    if (!mongoose.isValidObjectId(userId)) {
      return res.status(400).json({ success: false, error: 'Invalid user id' });
    }
    const now = new Date();
    if (!allowsReadReceipts(req.user.privacy)) {
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

export async function openViewOnce(req, res) {
  try {
    const { messageId } = req.params;
    if (!mongoose.isValidObjectId(messageId)) {
      return res.status(400).json({ success: false, error: 'Invalid message id' });
    }

    const existing = await Message.findById(messageId).populate('attachment');
    if (!existing) return res.status(404).json({ success: false, error: 'Message not found' });
    if (!existing.viewOnce) {
      return res.status(400).json({ success: false, error: 'Message is not view-once media' });
    }
    if (existing.viewOnceOpenedAt) {
      const populated = await Message.findById(existing._id)
        .populate('attachment', ATTACHMENT_POPULATE)
        .populate('replyTo', 'from forRecipient forSender envelopes group content createdAt');
      return res.json({ success: true, data: toClientMessage(populated) });
    }

    const uid = req.user._id.toString();
    const senderId = existing.from.toString();
    let isParty = false;
    let groupMemberIds = null;

    if (existing.group) {
      const Group = (await import('../models/Group.js')).default;
      const group = await Group.findById(existing.group);
      if (!group) return res.status(404).json({ success: false, error: 'Group not found' });
      groupMemberIds = group.members.map((m) => m.toString());
      isParty = groupMemberIds.includes(uid);
    } else if (existing.to) {
      isParty = [senderId, existing.to.toString()].includes(uid);
    }
    if (!isParty) return res.status(403).json({ success: false, error: 'Not authorized' });

    const attachmentId = existing.attachment?._id || existing.attachment;
    const viewOnceMediaKind =
      existing.viewOnceMediaKind ||
      (existing.attachment ? mediaKindFromAttachment(existing.attachment) : undefined);

    // Atomic claim so only one open wins across devices.
    const claimed = await Message.findOneAndUpdate(
      { _id: existing._id, viewOnce: true, viewOnceOpenedAt: null },
      {
        $set: {
          viewOnceOpenedAt: new Date(),
          viewOnceOpenedBy: req.user._id,
          ...(viewOnceMediaKind ? { viewOnceMediaKind } : {}),
        },
        $unset: { attachment: 1 },
      },
      { new: true },
    );

    if (!claimed) {
      const populated = await Message.findById(existing._id)
        .populate('attachment', ATTACHMENT_POPULATE)
        .populate('replyTo', 'from forRecipient forSender envelopes group content createdAt');
      return res.json({ success: true, data: toClientMessage(populated) });
    }

    await removeAttachmentFiles(attachmentId);

    const populated = await Message.findById(claimed._id)
      .populate('attachment', ATTACHMENT_POPULATE)
      .populate('replyTo', 'from forRecipient forSender envelopes group content createdAt');
    const payload = toClientMessage(populated);

    const io = req.app.get('io');
    if (existing.group && groupMemberIds) {
      for (const memberId of groupMemberIds) {
        io?.to(memberId).emit('message:view-once-opened', payload);
      }
    } else {
      emitToParticipants(io, existing, 'message:view-once-opened', payload);
    }

    res.json({ success: true, data: payload });
  } catch (err) {
    res.status(err.status || 500).json({ success: false, error: err.message });
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
    await User.updateMany(
      { 'importantMessages.messageId': message._id },
      { $pull: { importantMessages: { messageId: message._id } } },
    );

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

     if (!clear) {
      const reactorId = req.user._id.toString();
      if (groupMemberIds) {
        for (const memberId of groupMemberIds) {
          if (memberId === reactorId) continue;
          notifyUser(memberId, {
            title: 'QuantumChat',
            body: 'New reaction',
            kind: 'reaction',
            conversationKey: `group:${message.group}`,
            url: `/chat/g/${message.group}`,
            data: { messageId: message._id.toString(), fromUserId: reactorId },
          }).catch(() => {});
        }
      } else {
        const otherPartyId =
          message.from.toString() === reactorId ? message.to?.toString() : message.from.toString();
        if (otherPartyId && otherPartyId !== reactorId) {
          notifyUser(otherPartyId, {
            title: 'QuantumChat',
            body: 'New reaction',
            kind: 'reaction',
            conversationKey: conversationKey({ from: message.from, to: message.to }),
            url: `/chat/${reactorId}`,
            data: { messageId: message._id.toString(), fromUserId: reactorId },
          }).catch(() => {});
        }
      }
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

    const previousVersion = {
      editedAt: message.editedAt || message.createdAt,
      ...(message.group
        ? typeof message.content === 'string'
          ? { content: message.content }
          : { envelopes: message.envelopes }
        : { forRecipient: message.forRecipient, forSender: message.forSender }),
    };

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
        if (!Array.isArray(envelopes) || envelopes.length === 0) {
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
    message.editHistory = [...(message.editHistory || []), previousVersion];
    message.markModified('editHistory');
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
export async function getMessageInfo(req, res) {
  try {
    const { messageId } = req.params;
    const messageOid = toObjectId(messageId);
    if (!messageOid) {
      return res.status(400).json({ success: false, error: 'Invalid message id' });
    }
    const message = await Message.findById(messageOid);
    if (!message) return res.status(404).json({ success: false, error: 'Message not found' });

    const uid = req.user._id.toString();
    if (String(message.from) !== uid) {
      return res.status(403).json({ success: false, error: 'Only the sender can view message info' });
    }

    if (message.group) {
      const group = await Group.findById(message.group).populate(
        'members',
        'username displayName transliteratedNames avatarPath'
      );
      if (!group) return res.status(404).json({ success: false, error: 'Group not found' });

      const deliveredMap = new Map((message.deliveredTo || []).map((d) => [String(d.user), d.at]));
      const readMap = new Map((message.readBy || []).map((r) => [String(r.user), r.at]));

      const members = group.members
        .filter((m) => String(m._id) !== uid)
        .map((m) => ({
          userId: String(m._id),
          username: m.username,
          displayName: m.displayName || '',
          transliteratedNames: m.transliteratedNames || null,
          hasAvatar: Boolean(m.avatarPath),
          deliveredAt: deliveredMap.get(String(m._id)) || null,
          readAt: readMap.get(String(m._id)) || null,
        }));

      return res.json({
        success: true,
        data: {
          id: message._id.toString(),
          isGroup: true,
          totalRecipients: members.length,
          deliveredCount: members.filter((m) => m.deliveredAt || m.readAt).length,
          readCount: members.filter((m) => m.readAt).length,
          members,
        },
      });
    }

    return res.json({
      success: true,
      data: {
        id: message._id.toString(),
        isGroup: false,
        deliveredAt: message.deliveredAt || null,
        readAt: message.readAt || null,
      },
    });
  } catch (err) {
    res.status(err.status || 500).json({ success: false, error: err.message });
  }
}
