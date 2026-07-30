import User, { KEY_SET_SIZE } from '../models/User.js';
import Group from '../models/Group.js';
import Message from '../models/Message.js';
import Attachment from '../models/Attachment.js';
import FriendRequest from '../models/FriendRequest.js';
import mongoose from 'mongoose';
import { getStorage, newObjectName, safeImageContentType } from '../middleware/upload.js';
import { toObjectId } from '../utils/toObjectId.js';

const HEX_64 = /^[0-9a-f]{64}$/i;

const PUBLIC_FIELDS =
  'username displayName bio phone email publicKeys keyRotatedAt lastLoginAt blockedUsers friends avatarPath avatarMimeType privacy emailVerified isSystemUser systemRole verified';

export async function areUsersBlocked(userAId, userBId) {
  const aId = toObjectId(userAId);
  const bId = toObjectId(userBId);
  if (!aId || !bId) return true;
  const [a, b] = await Promise.all([
    User.findById(aId).select('blockedUsers'),
    User.findById(bId).select('blockedUsers'),
  ]);
  if (!a || !b) return true;
  const aBlocked = (a.blockedUsers || []).some((id) => String(id) === String(bId));
  const bBlocked = (b.blockedUsers || []).some((id) => String(id) === String(aId));
  return aBlocked || bBlocked;
}

export async function listUsers(req, res) {
  const blockedIds = (req.user.blockedUsers || []).map((id) => id);
  const friendIds = (req.user.friends || []).map((id) => String(id));
  const users = await User.find({
    _id: { $nin: [req.user._id, ...blockedIds] },
  }).select(PUBLIC_FIELDS);
  const visible = users.filter((u) => u.isSystemUser || friendIds.includes(String(u._id)));
  res.json({ success: true, data: visible.map((u) => u.toPublicJSON()) });
}

export async function getMe(req, res) {
  res.json({ success: true, data: req.user.toSelfJSON() });
}

/** Lightweight key-sync check: current server-advertised X5 public keys for the session user. */
export async function getMyPublicKeys(req, res) {
  const publicKeys = (req.user.publicKeys || []).map((k) => String(k).toLowerCase());
  res.json({
    success: true,
    data: {
      publicKeys,
      keyRotatedAt: req.user.keyRotatedAt || null,
    },
  });
}

export async function getUser(req, res) {
  const id = toObjectId(req.params.id);
  if (!id) return res.status(400).json({ success: false, error: 'Invalid user id' });
  const user = await User.findById(id).select(PUBLIC_FIELDS);
  if (!user) return res.status(404).json({ success: false, error: 'User not found' });
  if (await areUsersBlocked(req.user._id, user._id)) {
    return res.status(403).json({ success: false, error: 'User is blocked' });
  }
  res.json({ success: true, data: user.toPublicJSON() });
}
export async function updateProfile(req, res) {
  try {
    const { displayName, bio, phone, username, privacy } = req.body || {};
    const user = req.user;

    if (username != null) {
      const next = String(username).trim();
      if (next.length < 3 || next.length > 30) {
        return res.status(400).json({ success: false, error: 'Username must be 3-30 characters' });
      }
      if (next !== user.username) {
        const taken = await User.findOne({ username: next, _id: { $ne: user._id } }).select('_id');
        if (taken) return res.status(409).json({ success: false, error: 'Username already taken' });
        user.username = next;
      }
    }
    if (displayName != null) {
      if (typeof displayName !== 'string' || displayName.length > 60) {
        return res.status(400).json({ success: false, error: 'Display name must be under 60 characters' });
      }
      user.displayName = displayName.trim();
    }
    if (bio != null) {
      if (typeof bio !== 'string' || bio.length > 300) {
        return res.status(400).json({ success: false, error: 'Bio must be under 300 characters' });
      }
      user.bio = bio.trim();
    }
    if (phone != null) {
      if (typeof phone !== 'string' || phone.length > 32) {
        return res.status(400).json({ success: false, error: 'Phone must be under 32 characters' });
      }
      user.phone = phone.trim();
    }
    if (privacy && typeof privacy === 'object') {
      user.privacy = user.privacy || {};
      if (privacy.lastSeen === 'everyone' || privacy.lastSeen === 'nobody') {
        user.privacy.lastSeen = privacy.lastSeen;
      }
      if (privacy.online === 'everyone' || privacy.online === 'nobody') {
        user.privacy.online = privacy.online;
      }
      if (typeof privacy.readReceipts === 'boolean') {
        user.privacy.readReceipts = privacy.readReceipts;
      }
    }

    await user.save();
    res.json({ success: true, data: user.toSelfJSON() });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

export async function listBlockedUsers(req, res) {
  try {
    const me = await User.findById(req.user._id).populate('blockedUsers', 'username displayName avatarPath');
    const blocked = (me.blockedUsers || []).map((u) => ({
      id: u._id || u,
      username: u.username,
      displayName: u.displayName || '',
      hasAvatar: Boolean(u.avatarPath),
    }));
    res.json({ success: true, data: blocked });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

export async function blockUser(req, res) {
  const id = toObjectId(req.params.id);
  if (!id) {
    return res.status(400).json({ success: false, error: 'Invalid user id' });
  }
  if (String(id) === String(req.user._id)) {
    return res.status(400).json({ success: false, error: 'You cannot block yourself' });
  }

  const target = await User.findById(id).select('_id isSystemUser');
  if (!target) return res.status(404).json({ success: false, error: 'User not found' });
  if (target.isSystemUser) {
    return res.status(400).json({ success: false, error: 'System users cannot be blocked' });
  }

  await User.updateOne({ _id: req.user._id }, { $addToSet: { blockedUsers: target._id } });
  const me = await User.findById(req.user._id);
  res.json({ success: true, data: me.toSelfJSON() });
}

export async function unblockUser(req, res) {
  const id = toObjectId(req.params.id);
  if (!id) {
    return res.status(400).json({ success: false, error: 'Invalid user id' });
  }

  await User.updateOne({ _id: req.user._id }, { $pull: { blockedUsers: id } });
  const me = await User.findById(req.user._id);
  res.json({ success: true, data: me.toSelfJSON() });
}

export async function updatePublicKeys(req, res) {
  const { publicKeys } = req.body;
  const valid = Array.isArray(publicKeys) && publicKeys.length === KEY_SET_SIZE && publicKeys.every((k) => HEX_64.test(k));
  if (!valid) {
    return res.status(400).json({
      success: false,
      error: `publicKeys must be an array of ${KEY_SET_SIZE} 64-character hex X25519 public keys`,
    });
  }
  req.user.publicKeys = publicKeys.map((k) => k.toLowerCase());
  req.user.keyRotatedAt = new Date();
  await req.user.save();
  res.json({ success: true, data: req.user.toSelfJSON() });
}

export async function uploadAvatar(req, res) {
  try {
    if (!req.file?.buffer) {
      return res.status(400).json({ success: false, error: 'Image file is required' });
    }

    const storage = getStorage();
    const ext = (() => {
      const raw = String(req.file.originalname || '');
      const i = raw.lastIndexOf('.');
      return i >= 0 ? raw.slice(i).toLowerCase() : '.jpg';
    })();
    const objectName = newObjectName('avatars', ext === '.jpeg' ? '.jpg' : ext);
    const stored = await storage.put(
      req.file.buffer,
      objectName,
      safeImageContentType(req.file.mimetype),
      String(req.user._id)
    );

    if (req.user.avatarPath) {
      try {
        await storage.delete(req.user.avatarPath);
      } catch {
        // ignore
      }
    }

    req.user.avatarPath = stored.key;
    req.user.avatarStorageProvider = stored.provider;
    req.user.avatarMimeType = safeImageContentType(req.file.mimetype);
    await req.user.save();
    res.json({ success: true, data: req.user.toSelfJSON() });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

export async function deleteAvatar(req, res) {
  try {
    if (req.user.avatarPath) {
      try {
        await getStorage().delete(req.user.avatarPath);
      } catch {
        // ignore
      }
    }
    req.user.avatarPath = null;
    req.user.avatarStorageProvider = null;
    req.user.avatarMimeType = null;
    await req.user.save();
    res.json({ success: true, data: req.user.toSelfJSON() });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

export async function getAvatar(req, res) {
  try {
    const id = toObjectId(req.params.id);
    if (!id) {
      return res.status(400).json({ success: false, error: 'Invalid user id' });
    }
    const user = await User.findById(id).select('avatarPath avatarMimeType');
    if (!user?.avatarPath) {
      return res.status(404).json({ success: false, error: 'No avatar' });
    }
    const bytes = await getStorage().read(user.avatarPath);
    res.setHeader('Content-Type', safeImageContentType(user.avatarMimeType));
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Disposition', 'inline');
    res.setHeader('Cache-Control', 'private, max-age=3600');
    res.send(bytes);
  } catch (err) {
    if (!res.headersSent) {
      res.status(404).json({ success: false, error: 'Avatar file missing' });
    }
  }
}

export async function exportAccountData(req, res) {
  try {
    const user = await User.findById(req.user._id);
    const groups = await Group.find({ members: user._id }).select('name description createdAt createdBy members admins');
    const messageCount = await Message.countDocuments({
      $or: [{ from: user._id }, { to: user._id }, { 'envelopes.user': user._id }],
    });
    const attachmentCount = await Attachment.countDocuments({
      $or: [{ owner: user._id }, { recipient: user._id }],
    });

    const payload = {
      exportedAt: new Date().toISOString(),
      account: user.toSelfJSON(),
      groups: groups.map((g) => ({
        id: g._id,
        name: g.name,
        description: g.description,
        createdAt: g.createdAt,
        memberCount: (g.members || []).length,
      })),
      stats: { messageCount, attachmentCount },
      note: 'Message bodies are end-to-end encrypted and are not included. Use Export chat in the app to download decrypted conversations from this device.',
    };

    res.setHeader('Content-Disposition', 'attachment; filename="quantumchat-data.json"');
    res.json({ success: true, data: payload });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

export async function deleteAccount(req, res) {
  try {
    const { password } = req.body || {};
    if (!password) {
      return res.status(400).json({ success: false, error: 'password is required to delete your account' });
    }
    const user = await User.findById(req.user._id).select('+password');
    if (!user || !(await user.comparePassword(password))) {
      return res.status(401).json({ success: false, error: 'Password is incorrect' });
    }

    const userId = user._id;

    const groups = await Group.find({ members: userId });
    for (const group of groups) {
      group.members = group.members.filter((m) => String(m) !== String(userId));
      group.admins = (group.admins || []).filter((a) => String(a) !== String(userId));
      if (String(group.createdBy) === String(userId) && group.members.length) {
        group.createdBy = group.members[0];
        if (!group.admins.some((a) => String(a) === String(group.createdBy))) {
          group.admins.push(group.createdBy);
        }
      }
      if (group.members.length === 0) {
        await Message.deleteMany({ group: group._id });
        await group.deleteOne();
      } else {
        await group.save();
      }
    }

    await Message.deleteMany({ $or: [{ from: userId }, { to: userId }] });
    await User.updateMany({ blockedUsers: userId }, { $pull: { blockedUsers: userId } });
    await User.updateMany({ friends: userId }, { $pull: { friends: userId } });
    await FriendRequest.deleteMany({ $or: [{ from: userId }, { to: userId }] });

    if (user.avatarPath) {
      try {
        await getStorage().delete(user.avatarPath);
      } catch {
        // ignore
      }
    }

    await user.deleteOne();
    res.json({ success: true, data: { deleted: true } });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

/* ================================================================
   FRIEND REQUESTS / FRIENDS
   ================================================================ */

export async function discoverUsers(req, res) {
  try {
    const blockedIds = (req.user.blockedUsers || []).map((id) => String(id));
    const friendIds = (req.user.friends || []).map((id) => String(id));
    const q = typeof req.query.q === 'string' ? req.query.q.trim() : '';

    const filter = {
      _id: { $ne: req.user._id },
      isSystemUser: { $ne: true },
    };
    if (q) {
      filter.$or = [
        { username: { $regex: q, $options: 'i' } },
        { displayName: { $regex: q, $options: 'i' } },
      ];
    }

    const users = await User.find(filter).select(PUBLIC_FIELDS).limit(100);
    const candidates = users.filter(
      (u) => !blockedIds.includes(String(u._id)) && !friendIds.includes(String(u._id))
    );
    const candidateIds = candidates.map((u) => u._id);

    const requests = await FriendRequest.find({
      status: 'pending',
      $or: [
        { from: req.user._id, to: { $in: candidateIds } },
        { to: req.user._id, from: { $in: candidateIds } },
      ],
    });

    const statusByUserId = new Map();
    for (const r of requests) {
      if (String(r.from) === String(req.user._id)) {
        statusByUserId.set(String(r.to), { status: 'pending_sent', requestId: r._id });
      } else {
        statusByUserId.set(String(r.from), { status: 'pending_received', requestId: r._id });
      }
    }

    const data = candidates.map((u) => {
      const info = statusByUserId.get(String(u._id));
      return {
        ...u.toPublicJSON(),
        requestStatus: info?.status || 'none',
        requestId: info?.requestId || null,
      };
    });

    res.json({ success: true, data });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

async function acceptFriendRequestRecord(request, req) {
  request.status = 'accepted';
  await request.save();

  await Promise.all([
    User.updateOne({ _id: request.from }, { $addToSet: { friends: request.to } }),
    User.updateOne({ _id: request.to }, { $addToSet: { friends: request.from } }),
  ]);

  const [fromUser, toUser] = await Promise.all([
    User.findById(request.from).select(PUBLIC_FIELDS),
    User.findById(request.to).select(PUBLIC_FIELDS),
  ]);

  const io = req.app.get('io');
  io?.to(String(request.from)).emit('friend:request:accepted', {
    id: request._id,
    friend: toUser.toPublicJSON(),
  });
  io?.to(String(request.to)).emit('friend:request:accepted', {
    id: request._id,
    friend: fromUser.toPublicJSON(),
  });
}

export async function sendFriendRequest(req, res) {
  try {
    const { to } = req.body || {};
    const toId = toObjectId(to);
    if (!toId) {
      return res.status(400).json({ success: false, error: 'Invalid user id' });
    }
    if (String(toId) === String(req.user._id)) {
      return res.status(400).json({ success: false, error: 'You cannot friend yourself' });
    }

    const target = await User.findById(toId).select('_id isSystemUser');
    if (!target) return res.status(404).json({ success: false, error: 'User not found' });
    if (target.isSystemUser) {
      return res.status(400).json({ success: false, error: 'Cannot send a friend request to this account' });
    }
    if (await areUsersBlocked(req.user._id, target._id)) {
      return res.status(403).json({ success: false, error: 'Not allowed' });
    }

    const alreadyFriends = (req.user.friends || []).some((id) => String(id) === String(target._id));
    if (alreadyFriends) {
      return res.status(409).json({ success: false, error: 'Already friends' });
    }

    const existing = await FriendRequest.findOne({
      status: 'pending',
      $or: [
        { from: req.user._id, to: target._id },
        { from: target._id, to: req.user._id },
      ],
    });

    if (existing) {
      if (String(existing.from) === String(target._id)) {
        await acceptFriendRequestRecord(existing, req);
        return res.json({ success: true, data: { id: existing._id, status: 'accepted' } });
      }
      return res.status(409).json({ success: false, error: 'Friend request already sent' });
    }

    const request = await FriendRequest.create({ from: req.user._id, to: target._id, status: 'pending' });

    const io = req.app.get('io');
    io?.to(String(target._id)).emit('friend:request:new', {
      id: request._id,
      from: req.user.toPublicJSON(),
    });

    res.status(201).json({ success: true, data: { id: request._id, status: 'pending' } });
  } catch (err) {
    if (err?.code === 11000) {
      return res.status(409).json({ success: false, error: 'Friend request already exists' });
    }
    res.status(500).json({ success: false, error: err.message });
  }
}
export async function listFriendRequests(req, res) {
  try {
    const [incoming, outgoing] = await Promise.all([
      FriendRequest.find({ to: req.user._id, status: 'pending' }).populate('from', PUBLIC_FIELDS),
      FriendRequest.find({ from: req.user._id, status: 'pending' }).populate('to', PUBLIC_FIELDS),
    ]);
    res.json({
      success: true,
      data: {
        incoming: incoming.map((r) => ({ id: r._id, user: r.from.toPublicJSON(), createdAt: r.createdAt })),
        outgoing: outgoing.map((r) => ({ id: r._id, user: r.to.toPublicJSON(), createdAt: r.createdAt })),
      },
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

export async function acceptFriendRequest(req, res) {
  try {
    const id = toObjectId(req.params.id);
    if (!id) {
      return res.status(400).json({ success: false, error: 'Invalid request id' });
    }
    const request = await FriendRequest.findById(id);
    if (!request || request.status !== 'pending') {
      return res.status(404).json({ success: false, error: 'Friend request not found' });
    }
    if (String(request.to) !== String(req.user._id)) {
      return res.status(403).json({ success: false, error: 'Not authorized to accept this request' });
    }
    await acceptFriendRequestRecord(request, req);
    const me = await User.findById(req.user._id);
    res.json({ success: true, data: { id: request._id, status: 'accepted', me: me.toSelfJSON() } });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}
export async function declineFriendRequest(req, res) {
  try {
    const id = toObjectId(req.params.id);
    if (!id) {
      return res.status(400).json({ success: false, error: 'Invalid request id' });
    }
    const request = await FriendRequest.findById(id);
    if (!request || request.status !== 'pending') {
      return res.status(404).json({ success: false, error: 'Friend request not found' });
    }
    if (String(request.to) !== String(req.user._id)) {
      return res.status(403).json({ success: false, error: 'Not authorized to decline this request' });
    }
    request.status = 'declined';
    await request.save();
    res.json({ success: true, data: { id: request._id, status: 'declined' } });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

export async function cancelFriendRequest(req, res) {
  try {
    const id = toObjectId(req.params.id);
    if (!id) {
      return res.status(400).json({ success: false, error: 'Invalid request id' });
    }
    const request = await FriendRequest.findById(id);
    if (!request || request.status !== 'pending') {
      return res.status(404).json({ success: false, error: 'Friend request not found' });
    }
    if (String(request.from) !== String(req.user._id)) {
      return res.status(403).json({ success: false, error: 'Not authorized to cancel this request' });
    }
    await request.deleteOne();
    res.json({ success: true, data: { id, cancelled: true } });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

export async function removeFriend(req, res) {
  try {
    const id = toObjectId(req.params.id);
    if (!id) {
      return res.status(400).json({ success: false, error: 'Invalid user id' });
    }
    if (String(id) === String(req.user._id)) {
      return res.status(400).json({ success: false, error: 'Invalid request' });
    }

    const isFriend = (req.user.friends || []).some((f) => String(f) === String(id));
    if (!isFriend) {
      return res.status(404).json({ success: false, error: 'Not currently friends with this user' });
    }

    await Promise.all([
      User.updateOne({ _id: req.user._id }, { $pull: { friends: id } }),
      User.updateOne({ _id: id }, { $pull: { friends: req.user._id } }),
    ]);

    const io = req.app.get('io');
    io?.to(String(id)).emit('friend:removed', { by: String(req.user._id) });
    const me = await User.findById(req.user._id);
    res.json({ success: true, data: { id, removed: true, me: me.toSelfJSON() } });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}