import crypto from 'crypto';
import fs from 'fs';
import mongoose from 'mongoose';
import Group from '../models/Group.js';
import GroupJoinRequest from '../models/GroupJoinRequest.js';
import User from '../models/User.js';
import Message from '../models/Message.js';
import { resolveUploadPath, safeImageContentType } from '../middleware/upload.js';
import { sealForPublicKey } from '../utils/sealedBox.js';
import { isUserOnline } from '../socket/index.js';
import { notifyUser } from '../services/pushService.js';
import { incrementCiphertextsRelayed } from '../services/blindnessStats.js';
import { resolveExpiresAt, notExpiredFilter } from '../utils/messageExpiry.js';
import { toObjectId } from '../utils/toObjectId.js';

const HEX_64 = /^[0-9a-f]{64}$/i;
const ATTACHMENT_POPULATE =
  'filename mimetype size nonce ephemeralPublicKey targetPublicKey forSenderNonce forSenderEphemeralPublicKey forSenderTargetPublicKey encryption secretboxNonce group';
const MEMBER_POPULATE =
  'username email publicKeys lastLoginAt keyRotatedAt avatarPath isSystemUser systemRole verified';

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
  if (message.group) {
    message.group = message.group._id || message.group;
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
  message.mentionedUserIds = (message.mentionedUserIds || []).map((id) => String(id));
  message.pollVotes = (message.pollVotes || []).map((v) => ({
    user: String(v.user),
    optionIndex: v.optionIndex,
  }));
  message.kind = message.kind || 'text';
  return message;
}

function emitToMembers(io, memberIds, event, payload) {
  if (!io) return;
  for (const id of memberIds) {
    io.to(String(id)).emit(event, payload);
  }
}

async function loadGroup(id) {
  return Group.findById(id).populate('members', MEMBER_POPULATE);
}

function ensureAdmins(group) {
  if (!group.admins?.length) {
    group.admins = [group.createdBy];
  }
}

function makeInviteCode() {
  return crypto.randomBytes(6).toString('hex');
}

export async function createGroup(req, res) {
  try {
    const { name, memberIds, description, visibility: visibilityRaw, joinPolicy: joinPolicyRaw } = req.body;
    if (!name || typeof name !== 'string' || name.trim().length < 2) {
      return res.status(400).json({ success: false, error: 'Group name must be at least 2 characters' });
    }

    const visibility = visibilityRaw === 'public' ? 'public' : 'private';
    let joinPolicy = 'invite';
    if (visibility === 'public') {
      joinPolicy = joinPolicyRaw === 'request' ? 'request' : 'open';
    }

    const requestedIds = Array.isArray(memberIds) ? memberIds : [];
    const uniqueIds = [...new Set(requestedIds.map(String))].filter((id) => id !== req.user._id.toString());

    if (visibility === 'private' && uniqueIds.length < 1) {
      return res.status(400).json({ success: false, error: 'Select at least one other member' });
    }
    if (uniqueIds.some((id) => !mongoose.isValidObjectId(id))) {
      return res.status(400).json({ success: false, error: 'Invalid member id' });
    }

    if (uniqueIds.length) {
      const found = await User.find({ _id: { $in: uniqueIds } }).select('_id');
      if (found.length !== uniqueIds.length) {
        return res.status(400).json({ success: false, error: 'One or more members were not found' });
      }
    }

    const members = [req.user._id, ...uniqueIds];
    const group = await Group.create({
      name: name.trim(),
      description: typeof description === 'string' ? description.trim().slice(0, 500) : '',
      createdBy: req.user._id,
      members,
      admins: [req.user._id],
      visibility,
      joinPolicy,
    });

    const populated = await loadGroup(group._id);
    const payload = populated.toPublicJSON();
    emitToMembers(req.app.get('io'), members, 'group:new', payload);
    res.status(201).json({ success: true, data: payload });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

export async function discoverGroups(req, res) {
  try {
    const q = typeof req.query.q === 'string' ? req.query.q.trim() : '';
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 30, 1), 50);
    const filter = {
      visibility: 'public',
      members: { $ne: req.user._id },
    };
    if (q) {
      filter.$or = [
        { name: { $regex: q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), $options: 'i' } },
        { description: { $regex: q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), $options: 'i' } },
      ];
    }

    const groups = await Group.find(filter)
      .sort({ updatedAt: -1 })
      .limit(limit)
      .select('name description members photoPath visibility joinPolicy createdAt updatedAt createdBy');

    const groupIds = groups.map((g) => g._id);
    const pending = await GroupJoinRequest.find({
      group: { $in: groupIds },
      user: req.user._id,
      status: 'pending',
    }).select('group');
    const pendingSet = new Set(pending.map((r) => String(r.group)));

    res.json({
      success: true,
      data: groups.map((g) => ({
        id: g._id,
        name: g.name,
        description: g.description || '',
        memberCount: (g.members || []).length,
        hasPhoto: Boolean(g.photoPath),
        visibility: 'public',
        joinPolicy: g.joinPolicy === 'request' ? 'request' : 'open',
        joinRequestPending: pendingSet.has(String(g._id)),
        createdAt: g.createdAt,
        updatedAt: g.updatedAt,
      })),
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

export async function joinPublicGroup(req, res) {
  try {
    const { id } = req.params;
    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).json({ success: false, error: 'Invalid group id' });
    }
    const group = await Group.findById(id);
    if (!group) return res.status(404).json({ success: false, error: 'Group not found' });
    if (group.visibility !== 'public') {
      return res.status(400).json({ success: false, error: 'Only public groups can be joined this way' });
    }
    if (group.joinPolicy !== 'open') {
      return res.status(400).json({
        success: false,
        error: 'This group requires a join request',
      });
    }
    if (group.isMember(req.user._id)) {
      const populated = await loadGroup(group._id);
      return res.json({ success: true, data: populated.toPublicJSON(), alreadyMember: true });
    }
    group.members.push(req.user._id);
    await group.save();
    await GroupJoinRequest.deleteOne({ group: group._id, user: req.user._id });
    const populated = await loadGroup(group._id);
    const payload = populated.toPublicJSON();
    emitToMembers(req.app.get('io'), group.members, 'group:updated', payload);
    emitToMembers(req.app.get('io'), [req.user._id], 'group:new', payload);
    res.json({ success: true, data: payload });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

export async function createJoinRequest(req, res) {
  try {
    const { id } = req.params;
    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).json({ success: false, error: 'Invalid group id' });
    }
    const group = await Group.findById(id);
    if (!group) return res.status(404).json({ success: false, error: 'Group not found' });
    if (group.visibility !== 'public' || group.joinPolicy !== 'request') {
      return res.status(400).json({
        success: false,
        error: 'This group does not accept join requests',
      });
    }
    if (group.isMember(req.user._id)) {
      return res.status(400).json({ success: false, error: 'Already a member' });
    }

    const existing = await GroupJoinRequest.findOne({ group: group._id, user: req.user._id });
    if (existing) {
      if (existing.status === 'pending') {
        return res.json({
          success: true,
          data: { id: existing._id, status: 'pending', groupId: group._id },
        });
      }
      existing.status = 'pending';
      await existing.save();
      return res.status(201).json({
        success: true,
        data: { id: existing._id, status: 'pending', groupId: group._id },
      });
    }

    const created = await GroupJoinRequest.create({
      group: group._id,
      user: req.user._id,
      status: 'pending',
    });
    res.status(201).json({
      success: true,
      data: { id: created._id, status: 'pending', groupId: group._id },
    });
  } catch (err) {
    if (err?.code === 11000) {
      return res.status(409).json({ success: false, error: 'Join request already exists' });
    }
    res.status(500).json({ success: false, error: err.message });
  }
}

export async function listJoinRequests(req, res) {
  try {
    const { id } = req.params;
    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).json({ success: false, error: 'Invalid group id' });
    }
    const group = await Group.findById(id);
    if (!group) return res.status(404).json({ success: false, error: 'Group not found' });
    if (!group.isMember(req.user._id)) {
      return res.status(403).json({ success: false, error: 'Not a group member' });
    }
    ensureAdmins(group);
    if (!group.isAdmin(req.user._id)) {
      return res.status(403).json({ success: false, error: 'Only admins can view join requests' });
    }

    const requests = await GroupJoinRequest.find({ group: group._id, status: 'pending' })
      .sort({ createdAt: 1 })
      .populate('user', 'username email avatarPath verified');

    res.json({
      success: true,
      data: requests.map((r) => ({
        id: r._id,
        status: r.status,
        createdAt: r.createdAt,
        user: r.user?.toPublicJSON
          ? r.user.toPublicJSON()
          : {
              id: r.user?._id || r.user,
              username: r.user?.username,
              email: r.user?.email,
              hasAvatar: Boolean(r.user?.avatarPath),
              verified: Boolean(r.user?.verified),
            },
      })),
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

export async function acceptJoinRequest(req, res) {
  try {
    const { id, userId } = req.params;
    if (!mongoose.isValidObjectId(id) || !mongoose.isValidObjectId(userId)) {
      return res.status(400).json({ success: false, error: 'Invalid id' });
    }
    const group = await Group.findById(id);
    if (!group) return res.status(404).json({ success: false, error: 'Group not found' });
    if (!group.isMember(req.user._id)) {
      return res.status(403).json({ success: false, error: 'Not a group member' });
    }
    ensureAdmins(group);
    if (!group.isAdmin(req.user._id)) {
      return res.status(403).json({ success: false, error: 'Only admins can accept join requests' });
    }

    const request = await GroupJoinRequest.findOne({
      group: group._id,
      user: userId,
      status: 'pending',
    });
    if (!request) {
      return res.status(404).json({ success: false, error: 'Join request not found' });
    }

    if (!group.isMember(userId)) {
      group.members.push(userId);
      await group.save();
    }
    request.status = 'accepted';
    await request.save();

    const populated = await loadGroup(group._id);
    const payload = populated.toPublicJSON();
    emitToMembers(req.app.get('io'), group.members, 'group:updated', payload);
    emitToMembers(req.app.get('io'), [userId], 'group:new', payload);
    res.json({ success: true, data: payload });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

export async function rejectJoinRequest(req, res) {
  try {
    const { id, userId } = req.params;
    if (!mongoose.isValidObjectId(id) || !mongoose.isValidObjectId(userId)) {
      return res.status(400).json({ success: false, error: 'Invalid id' });
    }
    const group = await Group.findById(id);
    if (!group) return res.status(404).json({ success: false, error: 'Group not found' });
    if (!group.isMember(req.user._id)) {
      return res.status(403).json({ success: false, error: 'Not a group member' });
    }
    ensureAdmins(group);
    if (!group.isAdmin(req.user._id)) {
      return res.status(403).json({ success: false, error: 'Only admins can reject join requests' });
    }

    const request = await GroupJoinRequest.findOne({
      group: group._id,
      user: userId,
      status: 'pending',
    });
    if (!request) {
      return res.status(404).json({ success: false, error: 'Join request not found' });
    }
    request.status = 'rejected';
    await request.save();
    res.json({ success: true, data: { groupId: group._id, userId, status: 'rejected' } });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

export async function listGroups(req, res) {
  try {
    const groups = await Group.find({ members: req.user._id })
      .sort({ updatedAt: -1 })
      .populate('members', MEMBER_POPULATE);
    res.json({ success: true, data: groups.map((g) => g.toPublicJSON()) });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

export async function getGroup(req, res) {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) {
      return res.status(400).json({ success: false, error: 'Invalid group id' });
    }
    const group = await loadGroup(req.params.id);
    if (!group) return res.status(404).json({ success: false, error: 'Group not found' });
    if (!group.isMember(req.user._id)) {
      return res.status(403).json({ success: false, error: 'Not a group member' });
    }
    res.json({ success: true, data: group.toPublicJSON() });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

export async function previewInvite(req, res) {
  try {
    const code = String(req.params.code || '').trim().toLowerCase();
    if (!code) return res.status(400).json({ success: false, error: 'Invite code required' });
    const group = await Group.findOne({ inviteCode: code, inviteEnabled: true }).select(
      'name description members photoPath inviteEnabled'
    );
    if (!group) return res.status(404).json({ success: false, error: 'Invite not found or expired' });
    res.json({
      success: true,
      data: {
        name: group.name,
        description: group.description || '',
        memberCount: (group.members || []).length,
        hasPhoto: Boolean(group.photoPath),
        code,
      },
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

export async function joinViaInvite(req, res) {
  try {
    const code = String(req.body.code || req.params.code || '')
      .trim()
      .toLowerCase();
    if (!code) return res.status(400).json({ success: false, error: 'Invite code required' });
    const group = await Group.findOne({ inviteCode: code, inviteEnabled: true });
    if (!group) return res.status(404).json({ success: false, error: 'Invite not found or expired' });
    if (group.isMember(req.user._id)) {
      const populated = await loadGroup(group._id);
      return res.json({ success: true, data: populated.toPublicJSON(), alreadyMember: true });
    }
    group.members.push(req.user._id);
    await group.save();
    const populated = await loadGroup(group._id);
    const payload = populated.toPublicJSON();
    emitToMembers(req.app.get('io'), group.members, 'group:updated', payload);
    emitToMembers(req.app.get('io'), [req.user._id], 'group:new', payload);
    res.json({ success: true, data: payload });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

export async function updateGroup(req, res) {
  try {
    const { id } = req.params;
    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).json({ success: false, error: 'Invalid group id' });
    }
    const group = await Group.findById(id);
    if (!group) return res.status(404).json({ success: false, error: 'Group not found' });
    if (!group.isMember(req.user._id)) {
      return res.status(403).json({ success: false, error: 'Not a group member' });
    }
    ensureAdmins(group);
    if (!group.isAdmin(req.user._id)) {
      return res.status(403).json({ success: false, error: 'Only admins can update group settings' });
    }

    const { name, description, onlyAdminsCanPost, onlyAdminsCanAddMembers, quantumAI, joinPolicy, visibility } =
      req.body;
    if (visibility != null) {
      return res.status(400).json({
        success: false,
        error: 'Group visibility cannot be changed after creation',
      });
    }
    if (name != null) {
      if (typeof name !== 'string' || name.trim().length < 2 || name.trim().length > 60) {
        return res.status(400).json({ success: false, error: 'Group name must be 2-60 characters' });
      }
      group.name = name.trim();
    }
    if (description != null) {
      if (typeof description !== 'string' || description.length > 500) {
        return res.status(400).json({ success: false, error: 'Description must be under 500 characters' });
      }
      group.description = description.trim();
    }
    if (typeof onlyAdminsCanPost === 'boolean') group.onlyAdminsCanPost = onlyAdminsCanPost;
    if (typeof onlyAdminsCanAddMembers === 'boolean') group.onlyAdminsCanAddMembers = onlyAdminsCanAddMembers;
    if (joinPolicy != null) {
      if (group.visibility !== 'public') {
        return res.status(400).json({
          success: false,
          error: 'Join policy can only be changed on public groups',
        });
      }
      if (!['open', 'request'].includes(joinPolicy)) {
        return res.status(400).json({
          success: false,
          error: 'Public joinPolicy must be open or request',
        });
      }
      group.joinPolicy = joinPolicy;
    }
    if (quantumAI && typeof quantumAI === 'object') {
      const next = {
        enabled: typeof quantumAI.enabled === 'boolean' ? quantumAI.enabled : group.quantumAI?.enabled,
        invocationPolicy: ['members', 'admins'].includes(quantumAI.invocationPolicy)
          ? quantumAI.invocationPolicy
          : group.quantumAI?.invocationPolicy,
        maxContextMessages: Number.isInteger(quantumAI.maxContextMessages)
          ? Math.min(Math.max(quantumAI.maxContextMessages, 0), 20)
          : group.quantumAI?.maxContextMessages,
        dailyLimit: Number.isInteger(quantumAI.dailyLimit)
          ? Math.min(Math.max(quantumAI.dailyLimit, 1), 1000)
          : group.quantumAI?.dailyLimit,
      };
      group.quantumAI = next;
    }

    await group.save();
    const populated = await loadGroup(group._id);
    const payload = populated.toPublicJSON();
    emitToMembers(req.app.get('io'), group.members, 'group:updated', payload);
    res.json({ success: true, data: payload });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

export async function renameGroup(req, res) {
  req.body = { name: req.body?.name };
  return updateGroup(req, res);
}

export async function uploadGroupPhoto(req, res) {
  try {
    const { id } = req.params;
    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).json({ success: false, error: 'Invalid group id' });
    }
    if (!req.file) return res.status(400).json({ success: false, error: 'Photo required' });
    const group = await Group.findById(id);
    if (!group) {
      fs.unlink(req.file.path, () => {});
      return res.status(404).json({ success: false, error: 'Group not found' });
    }
    if (!group.isAdmin(req.user._id)) {
      fs.unlink(req.file.path, () => {});
      return res.status(403).json({ success: false, error: 'Only admins can change the group photo' });
    }
    if (group.photoPath) {
      try {
        fs.unlink(resolveUploadPath(group.photoPath), () => {});
      } catch {
        /* ignore */
      }
    }
    group.photoPath = `groups/${req.file.filename}`;
    group.photoMimeType = safeImageContentType(req.file.mimetype);
    await group.save();
    const populated = await loadGroup(group._id);
    const payload = populated.toPublicJSON();
    emitToMembers(req.app.get('io'), group.members, 'group:updated', payload);
    res.json({ success: true, data: payload });
  } catch (err) {
    if (req.file?.path) fs.unlink(req.file.path, () => {});
    res.status(500).json({ success: false, error: err.message });
  }
}

export async function getGroupPhoto(req, res) {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) {
      return res.status(400).json({ success: false, error: 'Invalid group id' });
    }
    const group = await Group.findById(req.params.id).select('photoPath photoMimeType members');
    if (!group?.photoPath) return res.status(404).json({ success: false, error: 'No photo' });
    if (!group.isMember(req.user._id)) {
      return res.status(403).json({ success: false, error: 'Not a group member' });
    }
    res.setHeader('Content-Type', safeImageContentType(group.photoMimeType));
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Disposition', 'inline');
    res.sendFile(resolveUploadPath(group.photoPath), (err) => {
      if (err && !res.headersSent) res.status(404).json({ success: false, error: 'Photo not found' });
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

export async function setInviteLink(req, res) {
  try {
    const { id } = req.params;
    const { enabled, rotate } = req.body || {};
    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).json({ success: false, error: 'Invalid group id' });
    }
    const group = await Group.findById(id);
    if (!group) return res.status(404).json({ success: false, error: 'Group not found' });
    if (!group.isAdmin(req.user._id)) {
      return res.status(403).json({ success: false, error: 'Only admins can manage invite links' });
    }
    ensureAdmins(group);
    if (enabled === false) {
      group.inviteEnabled = false;
    } else {
      group.inviteEnabled = true;
      if (!group.inviteCode || rotate) group.inviteCode = makeInviteCode();
    }
    await group.save();
    const populated = await loadGroup(group._id);
    const payload = populated.toPublicJSON();
    emitToMembers(req.app.get('io'), group.members, 'group:updated', payload);
    res.json({ success: true, data: payload });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

export async function addMembers(req, res) {
  try {
    const { id } = req.params;
    const { memberIds } = req.body;
    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).json({ success: false, error: 'Invalid group id' });
    }
    const group = await Group.findById(id);
    if (!group) return res.status(404).json({ success: false, error: 'Group not found' });
    if (!group.isMember(req.user._id)) {
      return res.status(403).json({ success: false, error: 'Not a group member' });
    }
    ensureAdmins(group);
    if (group.onlyAdminsCanAddMembers !== false && !group.isAdmin(req.user._id)) {
      return res.status(403).json({ success: false, error: 'Only admins can add members' });
    }
    const existing = new Set(group.members.map(String));
    const toAdd = [...new Set((memberIds || []).map(String))].filter(
      (mid) => !existing.has(mid) && mongoose.isValidObjectId(mid)
    );
    if (toAdd.length === 0) {
      return res.status(400).json({ success: false, error: 'No new members to add' });
    }
    const found = await User.find({ _id: { $in: toAdd } }).select('_id');
    if (found.length !== toAdd.length) {
      return res.status(400).json({ success: false, error: 'One or more members were not found' });
    }
    group.members.push(...toAdd);
    await group.save();
    const populated = await loadGroup(group._id);
    const payload = populated.toPublicJSON();
    emitToMembers(req.app.get('io'), group.members, 'group:updated', payload);
    for (const mid of toAdd) {
      emitToMembers(req.app.get('io'), [mid], 'group:new', payload);
    }
    res.json({ success: true, data: payload });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

export async function removeMember(req, res) {
  try {
    const { id, memberId } = req.params;
    if (!mongoose.isValidObjectId(id) || !mongoose.isValidObjectId(memberId)) {
      return res.status(400).json({ success: false, error: 'Invalid id' });
    }
    const group = await Group.findById(id);
    if (!group) return res.status(404).json({ success: false, error: 'Group not found' });
    ensureAdmins(group);
    const isSelf = memberId === req.user._id.toString();
    if (!isSelf && !group.isAdmin(req.user._id)) {
      return res.status(403).json({ success: false, error: 'Only admins can remove other members' });
    }
    if (!isSelf && String(group.createdBy) === memberId) {
      return res.status(403).json({ success: false, error: 'Cannot remove the group owner' });
    }
    const before = group.members.map(String);
    group.members = group.members.filter((m) => m.toString() !== memberId);
    group.admins = (group.admins || []).filter((a) => a.toString() !== memberId);
    if (group.members.length === 0) {
      if (group.photoPath) {
        try {
          fs.unlink(resolveUploadPath(group.photoPath), () => {});
        } catch {
          /* ignore */
        }
      }
      await group.deleteOne();
      await Message.deleteMany({ group: id });
      emitToMembers(req.app.get('io'), before, 'group:deleted', { id });
      return res.json({ success: true, data: { id, deleted: true } });
    }
    if (String(group.createdBy) === memberId) {
      group.createdBy = group.members[0];
      if (!group.admins.some((a) => String(a) === String(group.createdBy))) {
        group.admins.push(group.createdBy);
      }
    }
    if (!group.admins.length) group.admins = [group.createdBy];
    await group.save();
    const populated = await loadGroup(group._id);
    const payload = populated.toPublicJSON();
    emitToMembers(req.app.get('io'), before, 'group:updated', payload);
    if (!isSelf) {
      emitToMembers(req.app.get('io'), [memberId], 'group:deleted', { id });
    } else {
      emitToMembers(req.app.get('io'), [memberId], 'group:deleted', { id });
    }
    res.json({ success: true, data: payload });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

export async function addAdmin(req, res) {
  try {
    const { id, memberId } = req.params;
    if (!mongoose.isValidObjectId(id) || !mongoose.isValidObjectId(memberId)) {
      return res.status(400).json({ success: false, error: 'Invalid id' });
    }
    const group = await Group.findById(id);
    if (!group) return res.status(404).json({ success: false, error: 'Group not found' });
    ensureAdmins(group);
    if (!group.isAdmin(req.user._id)) {
      return res.status(403).json({ success: false, error: 'Only admins can promote members' });
    }
    if (!group.isMember(memberId)) {
      return res.status(400).json({ success: false, error: 'User is not a group member' });
    }
    if (!group.admins.some((a) => String(a) === String(memberId))) {
      group.admins.push(memberId);
      await group.save();
    }
    const populated = await loadGroup(group._id);
    const payload = populated.toPublicJSON();
    emitToMembers(req.app.get('io'), group.members, 'group:updated', payload);
    res.json({ success: true, data: payload });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

export async function removeAdmin(req, res) {
  try {
    const { id, memberId } = req.params;
    if (!mongoose.isValidObjectId(id) || !mongoose.isValidObjectId(memberId)) {
      return res.status(400).json({ success: false, error: 'Invalid id' });
    }
    const group = await Group.findById(id);
    if (!group) return res.status(404).json({ success: false, error: 'Group not found' });
    ensureAdmins(group);
    if (String(group.createdBy) !== String(req.user._id)) {
      return res.status(403).json({ success: false, error: 'Only the owner can demote admins' });
    }
    if (String(memberId) === String(group.createdBy)) {
      return res.status(400).json({ success: false, error: 'Cannot demote the group owner' });
    }
    group.admins = (group.admins || []).filter((a) => String(a) !== String(memberId));
    if (!group.admins.length) group.admins = [group.createdBy];
    await group.save();
    const populated = await loadGroup(group._id);
    const payload = populated.toPublicJSON();
    emitToMembers(req.app.get('io'), group.members, 'group:updated', payload);
    res.json({ success: true, data: payload });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

export async function pinMessage(req, res) {
  try {
    const { id, messageId } = req.params;
    if (!mongoose.isValidObjectId(id) || !mongoose.isValidObjectId(messageId)) {
      return res.status(400).json({ success: false, error: 'Invalid id' });
    }
    const group = await Group.findById(id);
    if (!group) return res.status(404).json({ success: false, error: 'Group not found' });
    if (!group.isMember(req.user._id)) {
      return res.status(403).json({ success: false, error: 'Not a group member' });
    }
    ensureAdmins(group);
    if (!group.isAdmin(req.user._id)) {
      return res.status(403).json({ success: false, error: 'Only admins can pin messages' });
    }
    const msg = await Message.findById(messageId);
    if (!msg || String(msg.group) !== String(id)) {
      return res.status(404).json({ success: false, error: 'Message not found in this group' });
    }
    const ids = (group.pinnedMessageIds || []).map(String);
    if (!ids.includes(String(messageId))) {
      group.pinnedMessageIds = [messageId, ...(group.pinnedMessageIds || [])].slice(0, 20);
      await group.save();
    }
    const populated = await loadGroup(group._id);
    const payload = populated.toPublicJSON();
    emitToMembers(req.app.get('io'), group.members, 'group:updated', payload);
    res.json({ success: true, data: payload });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

export async function unpinMessage(req, res) {
  try {
    const { id, messageId } = req.params;
    if (!mongoose.isValidObjectId(id) || !mongoose.isValidObjectId(messageId)) {
      return res.status(400).json({ success: false, error: 'Invalid id' });
    }
    const group = await Group.findById(id);
    if (!group) return res.status(404).json({ success: false, error: 'Group not found' });
    if (!group.isAdmin(req.user._id)) {
      return res.status(403).json({ success: false, error: 'Only admins can unpin messages' });
    }
    group.pinnedMessageIds = (group.pinnedMessageIds || []).filter((mid) => String(mid) !== String(messageId));
    await group.save();
    const populated = await loadGroup(group._id);
    const payload = populated.toPublicJSON();
    emitToMembers(req.app.get('io'), group.members, 'group:updated', payload);
    res.json({ success: true, data: payload });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

export async function deleteGroup(req, res) {
  try {
    const { id } = req.params;
    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).json({ success: false, error: 'Invalid group id' });
    }
    const group = await Group.findById(id);
    if (!group) return res.status(404).json({ success: false, error: 'Group not found' });
    if (String(group.createdBy) !== String(req.user._id)) {
      return res.status(403).json({ success: false, error: 'Only the owner can delete the group' });
    }
    const members = group.members.map(String);
    if (group.photoPath) {
      try {
        fs.unlink(resolveUploadPath(group.photoPath), () => {});
      } catch {
        /* ignore */
      }
    }
    await group.deleteOne();
    await Message.deleteMany({ group: id });
    emitToMembers(req.app.get('io'), members, 'group:deleted', { id });
    res.json({ success: true, data: { id, deleted: true } });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

export async function sendGroupMessage(req, res) {
  try {
    const { groupId } = req.params;
    const {
      envelopes,
      content: contentRaw,
      attachmentId,
      replyTo,
      kind,
      mentionedUserIds,
      expiresInSeconds,
      forwardPolicy: forwardPolicyRaw,
    } = req.body;
    if (!mongoose.isValidObjectId(groupId)) {
      return res.status(400).json({ success: false, error: 'Invalid group id' });
    }

    const group = await Group.findById(groupId);
    if (!group) return res.status(404).json({ success: false, error: 'Group not found' });
    if (!group.isMember(req.user._id)) {
      return res.status(403).json({ success: false, error: 'Not a group member' });
    }
    ensureAdmins(group);
    if (group.onlyAdminsCanPost && !group.isAdmin(req.user._id)) {
      return res.status(403).json({ success: false, error: 'Only admins can post in this group' });
    }

    const isPublic = group.visibility === 'public';
    const messageKind = ['text', 'announcement', 'poll', 'event', 'file', 'ai_note'].includes(kind)
      ? kind
      : 'text';
    if (messageKind === 'announcement' && !group.isAdmin(req.user._id)) {
      return res.status(403).json({ success: false, error: 'Only admins can post announcements' });
    }

    const expiresAt = resolveExpiresAt(expiresInSeconds);
    if (expiresAt === null) {
      return res.status(400).json({
        success: false,
        error: 'expiresInSeconds must be one of 30, 300, 3600, 86400, 604800',
      });
    }

    let replyToId;
    if (replyTo) {
      const replyOid = toObjectId(replyTo);
      if (!replyOid) {
        return res.status(400).json({ success: false, error: 'Invalid replyTo id' });
      }
      const parent = await Message.findById(replyOid);
      if (!parent || String(parent.group || '') !== String(groupId)) {
        return res.status(400).json({ success: false, error: 'Reply must be in the same group' });
      }
      replyToId = parent._id;
    }

    const memberSet = new Set(group.members.map((m) => m.toString()));
    let normalized;
    let content;

    if (isPublic) {
      if (typeof contentRaw !== 'string' || !contentRaw.trim()) {
        return res.status(400).json({
          success: false,
          error: 'Public group messages require non-empty content',
        });
      }
      content = contentRaw.trim().slice(0, 8000);
    } else {
      if (!Array.isArray(envelopes) || envelopes.length < 2) {
        return res.status(400).json({
          success: false,
          error: 'envelopes must include a sealed-box copy for each member',
        });
      }

      normalized = [];
      for (const item of envelopes) {
        const userId = item?.user != null ? String(item.user) : '';
        if (!memberSet.has(userId) || !mongoose.isValidObjectId(userId)) {
          return res.status(400).json({ success: false, error: 'Envelope user must be a group member' });
        }
        if (!validateEnvelope(item)) {
          return res.status(400).json({ success: false, error: 'Each envelope must be a valid sealed box' });
        }
        normalized.push({
          user: userId,
          ...normalizeEnvelope(item),
        });
      }

      const covered = new Set(normalized.map((e) => String(e.user)));
      for (const memberId of memberSet) {
        if (!covered.has(memberId)) {
          return res.status(400).json({ success: false, error: 'Missing sealed envelope for a group member' });
        }
      }
    }

    if (attachmentId && !mongoose.isValidObjectId(attachmentId)) {
      return res.status(400).json({ success: false, error: 'Invalid attachment id' });
    }

    const mentions = [...new Set((mentionedUserIds || []).map(String))].filter(
      (mid) => memberSet.has(mid) && mongoose.isValidObjectId(mid)
    );

    let forwardPolicy;
    if (forwardPolicyRaw != null && typeof forwardPolicyRaw === 'object') {
      const allowForward = forwardPolicyRaw.allowForward !== false;
      let forwardUntil;
      if (forwardPolicyRaw.forwardUntil != null && forwardPolicyRaw.forwardUntil !== '') {
        const d = new Date(forwardPolicyRaw.forwardUntil);
        if (Number.isNaN(d.getTime())) {
          return res.status(400).json({
            success: false,
            error: 'forwardPolicy.forwardUntil must be a valid date',
          });
        }
        forwardUntil = d;
      }
      forwardPolicy = { allowForward, ...(forwardUntil ? { forwardUntil } : {}) };
    }

    const created = await Message.create({
      from: req.user._id,
      group: group._id,
      ...(isPublic ? { content } : { envelopes: normalized }),
      attachment: attachmentId || undefined,
      replyTo: replyToId,
      kind: messageKind,
      mentionedUserIds: mentions,
      pollVotes: messageKind === 'poll' ? [] : undefined,
      expiresAt: expiresAt || undefined,
      ...(forwardPolicy ? { forwardPolicy } : {}),
    });

    group.updatedAt = new Date();
    await group.save();

    const message = await Message.findById(created._id)
      .populate('attachment', ATTACHMENT_POPULATE)
      .populate('replyTo', 'from forRecipient forSender envelopes group content createdAt kind');
    const payload = toClientMessage(message);
    const io = req.app.get('io');
    emitToMembers(io, [...memberSet], 'message:new', payload);
    for (const mid of mentions) {
      if (mid !== String(req.user._id)) {
        io?.to(mid).emit('mention:new', { groupId, messageId: payload.id, from: String(req.user._id) });
      }
    }

    const senderId = String(req.user._id);
    for (const mid of memberSet) {
      if (mid === senderId) continue;
      if (!isUserOnline(mid)) {
        notifyUser(mid, {
          title: 'QuantumChat',
          body: isPublic ? 'New public group message' : 'New group message',
        }).catch(() => {});
      }
    }

    if (!isPublic) incrementCiphertextsRelayed();
    res.status(201).json({ success: true, data: payload });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

export async function publishQuantumAIGroupResponse(req, res) {
  try {
    const { groupId } = req.params;
    const { content, contentHash, requestId: requestIdRaw, receipt, model } = req.body || {};
    const requestIdMatch = String(requestIdRaw || '').match(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
    );
    if (
      !mongoose.isValidObjectId(groupId) ||
      !/^[0-9a-f]{64}$/i.test(contentHash || '') ||
      !requestIdMatch ||
      typeof content !== 'string' ||
      !content.trim() ||
      content.length > 100_000
    ) {
      return res.status(400).json({ success: false, error: 'Invalid QuantumAI response payload' });
    }
    const requestId = requestIdMatch[0].toLowerCase();
    const secret = process.env.QUANTUM_AI_SERVICE_SECRET;
    if (!secret || secret.length < 32) {
      return res.status(503).json({ success: false, error: 'QuantumAI service is not configured' });
    }
    const expected = crypto
      .createHmac('sha256', secret)
      .update(`${req.user._id}:group:${groupId}:${String(contentHash).toLowerCase()}:${requestId}`)
      .digest();
    const received = Buffer.from(String(receipt || ''), 'hex');
    if (received.length !== expected.length || !crypto.timingSafeEqual(received, expected)) {
      return res.status(403).json({ success: false, error: 'Invalid QuantumAI service receipt' });
    }
    const actualHash = crypto.createHash('sha256').update(content, 'utf8').digest('hex');
    if (actualHash !== String(contentHash).toLowerCase()) {
      return res.status(403).json({ success: false, error: 'QuantumAI content hash mismatch' });
    }

    const group = await Group.findById(groupId);
    if (!group || !group.isMember(req.user._id)) {
      return res.status(403).json({ success: false, error: 'Not a group member' });
    }
    ensureAdmins(group);
    if (!group.quantumAI?.enabled) {
      return res.status(403).json({ success: false, error: 'QuantumAI is disabled for this group' });
    }
    if (group.quantumAI.invocationPolicy === 'admins' && !group.isAdmin(req.user._id)) {
      return res.status(403).json({ success: false, error: 'Only group admins can invoke QuantumAI' });
    }
    const usageDay = new Date().toISOString().slice(0, 10);
    if (group.quantumAI.usageDay !== usageDay) {
      await Group.updateOne(
        { _id: group._id },
        { $set: { 'quantumAI.usageDay': usageDay, 'quantumAI.usageCount': 0 } }
      );
      group.quantumAI.usageDay = usageDay;
      group.quantumAI.usageCount = 0;
    }
    const quantumAI = await User.findOne({ systemRole: 'quantum_ai', isSystemUser: true });
    if (!quantumAI || !group.isMember(quantumAI._id)) {
      return res.status(409).json({ success: false, error: 'Add QuantumAI to this group first' });
    }
    const memberSet = new Set(group.members.map(String));
    const isPublic = group.visibility === 'public';
    let normalized;
    if (!isPublic) {
      const memberUsers = await User.find({ _id: { $in: [...memberSet] } }).select('_id publicKeys');
      if (memberUsers.length !== memberSet.size || memberUsers.some((member) => !member.publicKeys?.length)) {
        return res.status(409).json({ success: false, error: 'Every group member needs an encryption key' });
      }
      normalized = memberUsers.map((member) => ({
        user: member._id,
        ...sealForPublicKey(content, member.publicKeys[0]),
      }));
    }
    if (await Message.exists({ 'aiMetadata.requestId': requestId })) {
      return res.status(409).json({ success: false, error: 'AI response already published' });
    }

    const reserved = await Group.findOneAndUpdate(
      {
        _id: group._id,
        'quantumAI.usageCount': { $lt: group.quantumAI.dailyLimit },
      },
      { $inc: { 'quantumAI.usageCount': 1 } },
      { new: true }
    );
    if (!reserved) {
      return res.status(429).json({ success: false, error: 'This group reached its daily QuantumAI limit' });
    }

    const created = await Message.create({
      from: quantumAI._id,
      group: group._id,
      ...(isPublic ? { content } : { envelopes: normalized }),
      kind: 'ai',
      aiMetadata: {
        contentHash: String(contentHash).toLowerCase(),
        requestedBy: req.user._id,
        model: typeof model === 'string' ? model.slice(0, 120) : undefined,
        requestId,
      },
    });
    const payload = toClientMessage(created);
    emitToMembers(req.app.get('io'), [...memberSet], 'message:new', payload);
    return res.status(201).json({ success: true, data: payload });
  } catch (err) {
    return res.status(err.status || 500).json({ success: false, error: err.message });
  }
}

export async function getGroupMessages(req, res) {
  try {
    const { groupId } = req.params;
    const groupOid = toObjectId(groupId);
    if (!groupOid) {
      return res.status(400).json({ success: false, error: 'Invalid group id' });
    }
    const group = await Group.findById(groupOid);
    if (!group) return res.status(404).json({ success: false, error: 'Group not found' });
    if (!group.isMember(req.user._id)) {
      return res.status(403).json({ success: false, error: 'Not a group member' });
    }

    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 80, 1), 200);
    const before = req.query.before ? new Date(req.query.before) : null;
    const filter = {
      $and: [{ group: groupOid }, notExpiredFilter()],
    };
    if (before && !Number.isNaN(before.getTime())) {
      filter.$and.push({ createdAt: { $lt: before } });
    }

    const rows = await Message.find(filter)
      .sort({ createdAt: -1 })
      .limit(limit + 1)
      .populate('attachment', ATTACHMENT_POPULATE)
      .populate('replyTo', 'from forRecipient forSender envelopes group content createdAt kind');

    const hasMore = rows.length > limit;
    const page = hasMore ? rows.slice(0, limit) : rows;
    page.reverse();

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

export async function votePoll(req, res) {
  try {
    const { messageId } = req.params;
    const optionIndex = Number(req.body?.optionIndex);
    if (!mongoose.isValidObjectId(messageId) || !Number.isInteger(optionIndex) || optionIndex < 0) {
      return res.status(400).json({ success: false, error: 'Valid messageId and optionIndex required' });
    }
    const message = await Message.findById(messageId);
    if (!message?.group || message.kind !== 'poll') {
      return res.status(404).json({ success: false, error: 'Poll not found' });
    }
    const group = await Group.findById(message.group);
    if (!group || !group.isMember(req.user._id)) {
      return res.status(403).json({ success: false, error: 'Not a group member' });
    }
    const votes = message.pollVotes || [];
    const existing = votes.find((v) => String(v.user) === String(req.user._id));
    if (existing) existing.optionIndex = optionIndex;
    else votes.push({ user: req.user._id, optionIndex });
    message.pollVotes = votes;
    await message.save();
    const populated = await Message.findById(message._id)
      .populate('attachment', ATTACHMENT_POPULATE)
      .populate('replyTo', 'from forRecipient forSender envelopes group content createdAt kind');
    const payload = toClientMessage(populated);
    emitToMembers(req.app.get('io'), group.members, 'message:poll', payload);
    res.json({ success: true, data: payload });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}
