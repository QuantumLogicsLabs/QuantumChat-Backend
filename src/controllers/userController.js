import User, { KEY_SET_SIZE } from '../models/User.js';
import Group from '../models/Group.js';
import Message from '../models/Message.js';
import Attachment from '../models/Attachment.js';
import mongoose from 'mongoose';
import fs from 'fs';
import { resolveUploadPath, safeImageContentType } from '../middleware/upload.js';
import { toObjectId } from '../utils/toObjectId.js';

const HEX_64 = /^[0-9a-f]{64}$/i;

const PUBLIC_FIELDS =
  'username displayName bio phone email publicKeys keyRotatedAt lastLoginAt blockedUsers avatarPath avatarMimeType privacy emailVerified isSystemUser systemRole verified';

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
  const users = await User.find({
    _id: { $nin: [req.user._id, ...blockedIds] },
  }).select(PUBLIC_FIELDS);
  res.json({ success: true, data: users.map((u) => u.toPublicJSON()) });
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
  const user = await User.findById(req.params.id).select(PUBLIC_FIELDS);
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
  const { id } = req.params;
  if (!mongoose.isValidObjectId(id)) {
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
  const { id } = req.params;
  if (!mongoose.isValidObjectId(id)) {
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
    if (!req.file) {
      return res.status(400).json({ success: false, error: 'Image file is required' });
    }

    const relativePath = `avatars/${req.file.filename}`;
    if (req.user.avatarPath) {
      try {
        fs.unlink(resolveUploadPath(req.user.avatarPath), () => {});
      } catch {
        // ignore
      }
    }

    req.user.avatarPath = relativePath;
    req.user.avatarMimeType = safeImageContentType(req.file.mimetype);
    await req.user.save();
    res.json({ success: true, data: req.user.toSelfJSON() });
  } catch (err) {
    if (req.file?.path) fs.unlink(req.file.path, () => {});
    res.status(500).json({ success: false, error: err.message });
  }
}

export async function deleteAvatar(req, res) {
  try {
    if (req.user.avatarPath) {
      try {
        fs.unlink(resolveUploadPath(req.user.avatarPath), () => {});
      } catch {
        // ignore
      }
    }
    req.user.avatarPath = null;
    req.user.avatarMimeType = null;
    await req.user.save();
    res.json({ success: true, data: req.user.toSelfJSON() });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

export async function getAvatar(req, res) {
  try {
    const { id } = req.params;
    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).json({ success: false, error: 'Invalid user id' });
    }
    const user = await User.findById(id).select('avatarPath avatarMimeType');
    if (!user?.avatarPath) {
      return res.status(404).json({ success: false, error: 'No avatar' });
    }
    const filePath = resolveUploadPath(user.avatarPath);
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ success: false, error: 'Avatar file missing' });
    }
    res.setHeader('Content-Type', safeImageContentType(user.avatarMimeType));
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Disposition', 'inline');
    res.setHeader('Cache-Control', 'private, max-age=3600');
    fs.createReadStream(filePath).pipe(res);
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
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

    // Leave groups / remove membership
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
    // Remove user from others' block lists
    await User.updateMany({ blockedUsers: userId }, { $pull: { blockedUsers: userId } });

    if (user.avatarPath) {
      try {
        fs.unlink(resolveUploadPath(user.avatarPath), () => {});
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
