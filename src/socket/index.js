import jwt from 'jsonwebtoken';
import CallSignal from '../models/CallSignal.js';
import DeviceSession from '../models/DeviceSession.js';
import User from '../models/User.js';
import { createNotification } from '../services/notificationService.js';
import { notifyUser } from '../services/pushService.js';
import { canUserInviteToCall, isSealedEnvelope } from '../utils/callEnvelope.js';
import { canRelayLiveSignal } from '../utils/liveAccess.js';
import { canViewerSeeUserOnline } from '../utils/presencePrivacy.js';
const onlineUsers = new Map(); // userId -> Set(socketId)

function setOnline(userId, socketId) {
  if (!onlineUsers.has(userId)) onlineUsers.set(userId, new Set());
  onlineUsers.get(userId).add(socketId);
}

function setOffline(userId, socketId) {
  const set = onlineUsers.get(userId);
  if (!set) return false;
  set.delete(socketId);
  if (set.size === 0) {
    onlineUsers.delete(userId);
    return true;
  }
  return false;
}

export function isUserOnline(userId) {
  return onlineUsers.has(String(userId));
}

export function getOnlineUserIds() {
  return [...onlineUsers.keys()];
}

export { canViewerSeeUserOnline } from '../utils/presencePrivacy.js';

async function broadcastPresence(io, userId, isOnline, lastLoginAtIso) {
  try {
    const user = await User.findById(userId).select('privacy friends');
    if (!user) return;

    const privacy = user.privacy || {};
    let setting = privacy.onlineStatus;
    if (!setting) {
      setting = privacy.online === 'nobody' ? 'selected' : (privacy.online || 'everyone');
    }

    if (setting === 'nobody') return;
    const friendIds = (user.friends || []).map((f) => String(f._id || f));
    const showLastSeenEveryone = (privacy.lastSeen || 'everyone') === 'everyone';

    if (setting === 'everyone') {
      const globalPayload = {
        userId,
        online: isOnline,
        ...(showLastSeenEveryone && lastLoginAtIso ? { lastLoginAt: lastLoginAtIso } : {}),
      };
      io.emit('presence:update', globalPayload);

      if (lastLoginAtIso && privacy.lastSeen === 'friends') {
        for (const fId of friendIds) {
          io.to(fId).emit('presence:update', { userId, online: isOnline, lastLoginAt: lastLoginAtIso });
        }
      }
      // Always tell the user's own devices their real last-seen, regardless of setting.
      if (lastLoginAtIso && !showLastSeenEveryone) {
        io.to(userId).emit('presence:update', { userId, online: isOnline, lastLoginAt: lastLoginAtIso });
      }
    } else if (setting === 'friends') {
      const targetIds = new Set([userId, ...friendIds]);
      for (const tId of targetIds) {
        const isSelf = tId === userId;
        const isFriend = friendIds.includes(tId);
        const showLastSeen = isSelf || privacy.lastSeen === 'everyone' || (privacy.lastSeen === 'friends' && isFriend);
        io.to(tId).emit('presence:update', {
          userId,
          online: isOnline,
          ...(showLastSeen && lastLoginAtIso ? { lastLoginAt: lastLoginAtIso } : {}),
        });
      }
    } else if (setting === 'selected') {
      const visibleTo = (privacy.onlineStatusVisibleTo || []).map((u) => String(u._id || u));
      const targetIds = new Set([userId, ...visibleTo]);
      for (const tId of targetIds) {
        const isSelf = tId === userId;
        const isFriend = friendIds.includes(tId);
        const showLastSeen = isSelf || privacy.lastSeen === 'everyone' || (privacy.lastSeen === 'friends' && isFriend);
        io.to(tId).emit('presence:update', {
          userId,
          online: isOnline,
          ...(showLastSeen && lastLoginAtIso ? { lastLoginAt: lastLoginAtIso } : {}),
        });
      }
    }
  } catch {
    // ignore
  }
}

export function attachSocket(io) {
  io.use(async (socket, next) => {
    try {
      const token = socket.handshake.auth?.token;
      if (!token) return next(new Error('Missing auth token'));

      const payload = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
      if (payload.purpose === '2fa') return next(new Error('2FA verification required'));
      const user = await User.findById(payload.id);
      if (!user) return next(new Error('User not found'));

      if (payload.sessionId) {
        const session = await DeviceSession.findOne({
          user: user._id,
          sessionId: String(payload.sessionId),
          revokedAt: null,
        });
        if (!session) return next(new Error('Session revoked or invalid'));
        socket.sessionId = session.sessionId;
      }

      socket.userId = user._id.toString();
      socket.typingIndicatorEnabled = user.privacy?.typingIndicator !== false;
      next();
    } catch (err) {
      next(new Error('Invalid or expired token'));
    }
  });

  io.on('connection', (socket) => {
    const userId = socket.userId;
    socket.join(userId);
    setOnline(userId, socket.id);

    (async () => {
      try {
        await User.findByIdAndUpdate(userId, {
          lastLoginAt: new Date(),
          presenceAt: new Date(),
        });
      } catch {
        // ignore
      }
      await broadcastPresence(io, userId, true);

      const ids = getOnlineUserIds();
      if (ids.length) {
        const users = await User.find({ _id: { $in: ids } }).select('privacy friends');
        const visibleIds = users
          .filter((u) => canViewerSeeUserOnline(u, userId))
          .map((u) => String(u._id));
        socket.emit('presence:snapshot', { onlineUserIds: visibleIds });
      } else {
        socket.emit('presence:snapshot', { onlineUserIds: [] });
      }
    })();

    async function sendPresenceSnapshot() {
      const ids = getOnlineUserIds();
      if (!ids.length) {
        socket.emit('presence:snapshot', { onlineUserIds: [] });
        return;
      }
      try {
        const users = await User.find({ _id: { $in: ids } }).select('privacy friends');
        const visibleIds = users
          .filter((u) => canViewerSeeUserOnline(u, userId))
          .map((u) => String(u._id));
        socket.emit('presence:snapshot', { onlineUserIds: visibleIds });
      } catch {
        socket.emit('presence:snapshot', { onlineUserIds: [] });
      }
    }

    socket.on('presence:request', () => {
      sendPresenceSnapshot();
    });

    socket.on('typing:start', ({ to, groupId } = {}) => {
      if (socket.typingIndicatorEnabled === false) return;
      if (groupId) {
        io.to(`group:${String(groupId)}`).emit('typing:start', { from: userId, groupId: String(groupId) });
        return;
      }
      if (!to) return;
      io.to(String(to)).emit('typing:start', { from: userId });
    });

    socket.on('typing:stop', ({ to, groupId } = {}) => {
      if (socket.typingIndicatorEnabled === false) return;
      if (groupId) {
        io.to(`group:${String(groupId)}`).emit('typing:stop', { from: userId, groupId: String(groupId) });
        return;
      }
      if (!to) return;
      io.to(String(to)).emit('typing:stop', { from: userId });
    });

    socket.on('privacy:typing-indicator', ({ enabled } = {}) => {
      if (typeof enabled === 'boolean') {
        socket.typingIndicatorEnabled = enabled;
      }
    });

    socket.on('group:join', ({ groupId } = {}) => {
      if (!groupId) return;
      socket.join(`group:${String(groupId)}`);
    });

    socket.on('group:leave', ({ groupId } = {}) => {
      if (!groupId) return;
      socket.leave(`group:${String(groupId)}`);
    });

    async function relaySealedEnvelope(eventName, payload = {}) {
      const { to, callId, envelope } = payload;
      if (!to || !callId) return;
      if (payload.sdp != null || payload.candidate != null) return;
      if (!isSealedEnvelope(envelope)) return;

      if (eventName === 'call:invite' || eventName === 'meeting:invite') {
        const allowed = await canUserInviteToCall(userId, to);
        if (!allowed) return;
      }
      if (eventName.startsWith('live:')) {
        const allowed = await canRelayLiveSignal(userId, to, callId).catch(() => false);
        if (!allowed) return;
      }

      io.to(String(to)).emit(eventName, {
        from: userId,
        callId: String(callId),
        envelope,
      });
      if (eventName === 'call:invite' || eventName === 'meeting:invite') {
        const isMeeting = eventName === 'meeting:invite';
        notifyUser(to, {
          title: 'QuantumChat',
          body: isMeeting ? 'Incoming meeting' : 'Incoming call',
          kind: 'call',
          tag: `${isMeeting ? 'meeting' : 'call'}:${callId}`,
          url: '/chat',
          requireInteraction: true,
        }).catch(() => {});
      }
      // Missed-call detection (1:1 calls only). Persist the few events that
      // matter, then at hangup check whether it was ever actually answered.
      if (['call:invite', 'call:accept', 'call:hangup'].includes(eventName)) {
        CallSignal.create({ from: userId, to, callId: String(callId), event: eventName, envelope }).catch(() => {});
      }
      if (eventName === 'call:hangup') {
        (async () => {
          try {
            const callIdStr = String(callId);
            const [wasInviter, hadAccept] = await Promise.all([
              CallSignal.exists({ callId: callIdStr, event: 'call:invite', from: userId }),
              CallSignal.exists({ callId: callIdStr, event: 'call:accept' }),
            ]);
            // Only the original caller giving up before any accept counts as
            // "missed" — the callee hanging up after answering doesn't.
            if (wasInviter && !hadAccept) {
              createNotification({
                recipient: to,
                actor: userId,
                type: 'MISSED_CALL',
                entityType: 'call',
                entityId: callIdStr,
                metadata: { callId: callIdStr },
                io,
              }).catch(() => {});
            }
          } catch {
            // Best-effort — never worth failing the actual hangup relay over.
          }
        })();
      }
    }

    socket.on('call:invite', (payload = {}) => relaySealedEnvelope('call:invite', payload));
    socket.on('call:accept', (payload = {}) => relaySealedEnvelope('call:accept', payload));
    socket.on('call:reject', (payload = {}) => relaySealedEnvelope('call:reject', payload));
    socket.on('call:hangup', (payload = {}) => relaySealedEnvelope('call:hangup', payload));
    socket.on('call:offer', (payload = {}) => relaySealedEnvelope('call:offer', payload));
    socket.on('call:answer', (payload = {}) => relaySealedEnvelope('call:answer', payload));
    socket.on('call:ice', (payload = {}) => relaySealedEnvelope('call:ice', payload));

    socket.on('meeting:invite', (payload = {}) => relaySealedEnvelope('meeting:invite', payload));
    socket.on('meeting:join', (payload = {}) => relaySealedEnvelope('meeting:join', payload));
    socket.on('meeting:leave', (payload = {}) => relaySealedEnvelope('meeting:leave', payload));
    socket.on('meeting:end', (payload = {}) => relaySealedEnvelope('meeting:end', payload));
    socket.on('meeting:offer', (payload = {}) => relaySealedEnvelope('meeting:offer', payload));
    socket.on('meeting:answer', (payload = {}) => relaySealedEnvelope('meeting:answer', payload));
    socket.on('meeting:ice', (payload = {}) => relaySealedEnvelope('meeting:ice', payload));

    // Live streams: host <-> admitted viewer only (enforced in relaySealedEnvelope).
    socket.on('live:offer', (payload = {}) => relaySealedEnvelope('live:offer', payload));
    socket.on('live:answer', (payload = {}) => relaySealedEnvelope('live:answer', payload));
    socket.on('live:ice', (payload = {}) => relaySealedEnvelope('live:ice', payload));
    socket.on('live:leave', (payload = {}) => relaySealedEnvelope('live:leave', payload));
    socket.on('live:end', (payload = {}) => relaySealedEnvelope('live:end', payload));
    socket.on('message:delivered', async ({ messageId } = {}) => {
      try {
        if (!messageId) return;
        const Message = (await import('../models/Message.js')).default;
        const msg = await Message.findById(messageId);
        if (!msg) return;

        if (msg.group) {
          if (String(msg.from) === userId) return;
          const already = (msg.deliveredTo || []).some((d) => String(d.user) === userId);
          if (already) return;
          const now = new Date();
          await Message.updateOne(
            { _id: msg._id, 'deliveredTo.user': { $ne: userId } },
            { $push: { deliveredTo: { user: userId, at: now } } }
          );
          io.to(`group:${String(msg.group)}`).emit('message:status', {
            groupId: String(msg.group),
            userId,
            messageIds: [String(msg._id)],
            deliveredAt: now,
          });
          return;
        }

        if (String(msg.to) !== userId) return;
        if (msg.deliveredAt) return;
        msg.deliveredAt = new Date();
        await msg.save();
        const payload = {
          id: msg._id.toString(),
          deliveredAt: msg.deliveredAt,
          readAt: msg.readAt || null,
        };
        io.to(String(msg.from)).emit('message:status', payload);
        io.to(userId).emit('message:status', payload);
      } catch {
        // ignore
      }
    });

    socket.on('message:read', async ({ messageId, groupId } = {}) => {
      try {
        const Message = (await import('../models/Message.js')).default;
        const now = new Date();

        if (groupId) {
          const Group = (await import('../models/Group.js')).default;
          const group = await Group.findById(groupId).select('members');
          if (!group || !group.isMember(userId)) return;

          const query = messageId
            ? { _id: messageId, group: groupId, from: { $ne: userId }, 'readBy.user': { $ne: userId } }
            : { group: groupId, from: { $ne: userId }, 'readBy.user': { $ne: userId } };

          const unread = await Message.find(query).select('_id');
          const unreadIds = unread.map((m) => m._id);
          if (!unreadIds.length) return;

          await Promise.all([
            Message.updateMany(
              { _id: { $in: unreadIds }, 'deliveredTo.user': { $ne: userId } },
              { $push: { deliveredTo: { user: userId, at: now } } }
            ),
            Message.updateMany(
              { _id: { $in: unreadIds }, 'readBy.user': { $ne: userId } },
              { $push: { readBy: { user: userId, at: now } } }
            ),
          ]);

          io.to(`group:${String(groupId)}`).emit('message:status', {
            groupId: String(groupId),
            userId,
            messageIds: unreadIds.map(String),
            deliveredAt: now,
            readAt: now,
          });
          return;
        }

        if (messageId) {
          const msg = await Message.findById(messageId);
          if (!msg) return;

          if (msg.group) {
            if (String(msg.from) === userId) return;
            const already = (msg.readBy || []).some((r) => String(r.user) === userId);
            if (already) return;
            await Promise.all([
              Message.updateOne(
                { _id: msg._id, 'deliveredTo.user': { $ne: userId } },
                { $push: { deliveredTo: { user: userId, at: now } } }
              ),
              Message.updateOne(
                { _id: msg._id, 'readBy.user': { $ne: userId } },
                { $push: { readBy: { user: userId, at: now } } }
              ),
            ]);
            io.to(`group:${String(msg.group)}`).emit('message:status', {
              groupId: String(msg.group),
              userId,
              messageIds: [String(msg._id)],
              deliveredAt: now,
              readAt: now,
            });
            return;
          }

          if (String(msg.to) !== userId) return;
          if (msg.readAt) return;
          msg.deliveredAt = msg.deliveredAt || now;
          msg.readAt = now;
          await msg.save();
          const payload = {
            id: msg._id.toString(),
            deliveredAt: msg.deliveredAt,
            readAt: msg.readAt,
          };
          io.to(String(msg.from)).emit('message:status', payload);
          io.to(userId).emit('message:status', payload);
        }
      } catch {
        // ignore
      }
    });

    socket.on('disconnect', async () => {
      socket.leave(userId);
      const wentOffline = setOffline(userId, socket.id);
      if (wentOffline) {
        const lastLoginAt = new Date();
        try {
          await User.findByIdAndUpdate(userId, {
            lastLoginAt,
            presenceAt: lastLoginAt,
          });
        } catch {
          // ignore
        }
        await broadcastPresence(io, userId, false, lastLoginAt.toISOString());
      }
    });
  });
}
