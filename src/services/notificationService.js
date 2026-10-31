import Notification from '../models/Notification.js';
import User from '../models/User.js';
import { notifyUser } from './pushService.js';

/**
 * The one place that creates a Notification row. Every future event source
 * (friend requests, reactions, group mentions, story mentions, ...) should
 * call this rather than writing to the model directly, so the "never
 * notify yourself" rule and the live socket + push fan-out can't be
 * forgotten at a new call site.
 *
 * `push`, if given, is passed straight through to notifyUser() — same
 * shape used everywhere else in the app (title/body/kind/conversationKey/
 * actions/data). Pass nothing to skip the push and only persist + emit the
 * in-app event (e.g. for something that already sends its own push, like
 * story mentions piggybacking on sendStoryMentionMessages's DM push).
 */
export async function createNotification({
  recipient,
  actor,
  type,
  entityType,
  entityId,
  metadata,
  expiresAt,
  io,
  push,
}) {
  const recipientId = String(recipient);
  const actorId = actor ? String(actor) : null;
  if (actorId && actorId === recipientId) return null;

  const doc = await Notification.create({
    recipient: recipientId,
    actor: actorId,
    type,
    entityType,
    entityId,
    metadata,
    expiresAt: expiresAt || null,
  });

  if (io) {
    io.to(recipientId).emit('notification:new', doc.toPublicJSON());
  }

  if (push) {
    notifyUser(recipientId, push).catch(() => {});
  }

  return doc;
}

/**
 * True when the user has at least one live socket connected. Every
 * authenticated socket joins a room named after its user id (that's what
 * every `io.to(userId).emit(...)` in the codebase relies on), so the room
 * existing and being non-empty means "has the app open somewhere right
 * now".
 *
 * If `io` isn't available at all (e.g. a serverless request handler that
 * isn't the process holding the sockets) we can't tell, so this returns
 * false and callers fall back to "treat as offline" — the notification
 * then simply gets created and is cleared the moment the conversation is
 * read (see clearMessageNotifications).
 */
export function isUserOnline(io, userId) {
  const rooms = io?.sockets?.adapter?.rooms;
  if (!rooms) return false;
  const room = rooms.get(String(userId));
  return Boolean(room && room.size > 0);
}

/**
 * One rolled-up "X sent you N messages" row per (recipient, conversation)
 * instead of one row per message — otherwise a chatty friend would bury the
 * whole Activity feed. Replaces the existing unread row for that
 * conversation with a fresh one carrying count + 1, so it also moves back to
 * the top of the feed. Contains no message text, only a count, which keeps
 * this compatible with the end-to-end encryption model (the server never
 * has plaintext to put here in the first place).
 */
export async function upsertMessageNotification({ recipient, actor, conversationKey, messageId, io }) {
  const recipientId = String(recipient);
  const actorId = String(actor);
  if (recipientId === actorId) return null;
   const recipientDoc = await User.findById(recipientId).select('lockedChats').lean();
    if (recipientDoc?.lockedChats?.some((l) => l.conversationKey === conversationKey)) return null;


  const existing = await Notification.findOneAndDelete({
    recipient: recipientId,
    type: 'NEW_MESSAGE',
    readAt: null,
    'metadata.conversationKey': conversationKey,
  });
  const previousCount = Number(existing?.metadata?.count) || 0;

  const doc = await Notification.create({
    recipient: recipientId,
    actor: actorId,
    type: 'NEW_MESSAGE',
    entityType: 'message',
    entityId: messageId,
    metadata: { conversationKey, count: previousCount + 1 },
  });

  if (io) {
    io.to(recipientId).emit('notification:new', doc.toPublicJSON());
  }
  return doc;
}

/** Marks the rolled-up new-message row for one conversation as read. */
export async function clearMessageNotifications(userId, conversationKey) {
  const result = await Notification.updateMany(
    {
      recipient: userId,
      type: 'NEW_MESSAGE',
      readAt: null,
      'metadata.conversationKey': conversationKey,
    },
    { $set: { readAt: new Date() } }
  );
  return result.modifiedCount;
}

export async function getUnreadCount(userId) {
  return Notification.countDocuments({ recipient: userId, readAt: null });
}

export async function listNotifications(userId, { before, limit = 30, unreadOnly = false } = {}) {
  const query = { recipient: userId };
  if (unreadOnly) query.readAt = null;
  if (before) {
    const beforeDate = new Date(before);
    if (!Number.isNaN(beforeDate.getTime())) query.createdAt = { $lt: beforeDate };
  }
  const cap = Math.min(Math.max(Number(limit) || 30, 1), 100);
  return Notification.find(query)
    .sort({ createdAt: -1 })
    .limit(cap)
    .populate('actor', 'username avatarPath');
}

export async function markRead(userId, ids) {
  const list = (Array.isArray(ids) ? ids : [ids]).map(String);
  const result = await Notification.updateMany(
    { _id: { $in: list }, recipient: userId, readAt: null },
    { $set: { readAt: new Date() } }
  );
  return result.modifiedCount;
}

export async function markAllRead(userId) {
  const result = await Notification.updateMany(
    { recipient: userId, readAt: null },
    { $set: { readAt: new Date() } }
  );
  return result.modifiedCount;
}   