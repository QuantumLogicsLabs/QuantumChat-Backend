import bcrypt from 'bcryptjs';
import User from '../models/User.js';
import Group from '../models/Group.js';
import { parseConversationKey } from '../utils/conversationKey.js';
import { toObjectId } from '../utils/toObjectId.js';

const PIN_RE = /^\d{4,8}$/;
const MAX_ATTEMPTS = 5;
const LOCKOUT_MS = 15 * 60 * 1000;
const MAX_LOCKED_CHATS = 100;

function validPin(pin) {
  return typeof pin === 'string' && PIN_RE.test(pin);
}

/**
 * Checks a PIN against the user's stored hash while enforcing the per-account
 * lockout. Returns { ok: true } or { ok: false, status, error }.
 * `user` must have been loaded with +chatLockPinHash +chatLockFailedAttempts
 * +chatLockLockedUntil.
 */
async function checkPin(user, pin) {
  if (user.chatLockLockedUntil && user.chatLockLockedUntil > new Date()) {
    const minutes = Math.ceil((user.chatLockLockedUntil - Date.now()) / 60000);
    return { ok: false, status: 429, error: `Too many wrong PINs. Try again in ${minutes} minute(s).` };
  }
  const ok = validPin(pin) && (await user.compareChatLockPin(pin));
  if (ok) {
    if (user.chatLockFailedAttempts || user.chatLockLockedUntil) {
      user.chatLockFailedAttempts = 0;
      user.chatLockLockedUntil = null;
      await user.save();
    }
    return { ok: true };
  }
  user.chatLockFailedAttempts = (user.chatLockFailedAttempts || 0) + 1;
  if (user.chatLockFailedAttempts >= MAX_ATTEMPTS) {
    user.chatLockFailedAttempts = 0;
    user.chatLockLockedUntil = new Date(Date.now() + LOCKOUT_MS);
  }
  await user.save();
  return { ok: false, status: 403, error: 'Incorrect PIN' };
}

const PIN_FIELDS = '+chatLockPinHash +chatLockFailedAttempts +chatLockLockedUntil';

export async function getChatLockStatus(req, res) {
  try {
    const user = await User.findById(req.user._id).select('chatLockEnabled lockedChats');
    res.json({
      success: true,
      data: {
        chatLockEnabled: Boolean(user?.chatLockEnabled),
        lockedChats: (user?.lockedChats || []).map((l) => l.conversationKey),
      },
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

export async function setChatLockPin(req, res) {
  try {
    const { pin, currentPin } = req.body || {};
    if (!validPin(pin)) {
      return res.status(400).json({ success: false, error: 'PIN must be 4 to 8 digits' });
    }
    const user = await User.findById(req.user._id).select(PIN_FIELDS + ' chatLockEnabled');
    if (!user) return res.status(404).json({ success: false, error: 'User not found' });

    // Changing an existing PIN requires the current one.
    if (user.chatLockEnabled) {
      const check = await checkPin(user, currentPin);
      if (!check.ok) return res.status(check.status).json({ success: false, error: check.error });
    }

    user.chatLockPinHash = await bcrypt.hash(pin, 10);
    user.chatLockEnabled = true;
    await user.save();
    res.json({ success: true, data: { chatLockEnabled: true } });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

export async function verifyChatLockPin(req, res) {
  try {
    const user = await User.findById(req.user._id).select(PIN_FIELDS + ' chatLockEnabled');
    if (!user?.chatLockEnabled) {
      return res.status(404).json({ success: false, error: 'Chat Lock is not set up' });
    }
    const check = await checkPin(user, req.body?.pin);
    if (!check.ok) return res.status(check.status).json({ success: false, error: check.error });
    res.json({ success: true, data: { unlocked: true, chatLockToken: user.createChatLockToken() } });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

export async function disableChatLock(req, res) {
  try {
    const user = await User.findById(req.user._id).select(PIN_FIELDS + ' chatLockEnabled lockedChats');
    if (!user?.chatLockEnabled) {
      return res.status(400).json({ success: false, error: 'Chat Lock is not enabled' });
    }
    const check = await checkPin(user, req.body?.pin);
    if (!check.ok) return res.status(check.status).json({ success: false, error: check.error });

    user.chatLockEnabled = false;
    user.chatLockPinHash = null;
    user.lockedChats = [];
    await user.save();
    res.json({ success: true, data: { chatLockEnabled: false, lockedChats: [] } });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

/** The caller must be a party to the DM or a member of the group. */
async function canLockConversation(userId, key) {
  const parts = parseConversationKey(key);
  if (!parts) return false;
  if (parts.dm) return parts.dm.map(String).includes(String(userId));
  if (parts.group) {
    const gid = toObjectId(parts.group);
    if (!gid) return false;
    const group = await Group.findById(gid).select('members');
    return Boolean(group && group.isMember(userId));
  }
  return false;
}

export async function lockChat(req, res) {
  try {
    const key = req.body?.conversationKey;
    if (typeof key !== 'string' || !(await canLockConversation(req.user._id, key))) {
      return res.status(400).json({ success: false, error: 'Invalid conversation' });
    }
    const user = await User.findById(req.user._id).select('chatLockEnabled lockedChats');
    if (!user?.chatLockEnabled) {
      return res.status(400).json({ success: false, error: 'Set a Chat Lock PIN first' });
    }
    if (!user.lockedChats.some((l) => l.conversationKey === key)) {
      if (user.lockedChats.length >= MAX_LOCKED_CHATS) {
        return res.status(400).json({ success: false, error: 'Too many locked chats' });
      }
      user.lockedChats.push({ conversationKey: key, addedAt: new Date() });
      await user.save();
    }
    res.json({ success: true, data: { locked: true, conversationKey: key } });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

export async function unlockChat(req, res) {
  try {
    const key = req.body?.conversationKey;
    if (typeof key !== 'string' || !key) {
      return res.status(400).json({ success: false, error: 'conversationKey is required' });
    }
    const user = await User.findById(req.user._id).select(PIN_FIELDS + ' chatLockEnabled lockedChats');
    if (!user?.chatLockEnabled) {
      return res.status(400).json({ success: false, error: 'Chat Lock is not enabled' });
    }
    // Removing a lock needs the PIN, so a borrowed phone can't strip it.
    const check = await checkPin(user, req.body?.pin);
    if (!check.ok) return res.status(check.status).json({ success: false, error: check.error });

    user.lockedChats = user.lockedChats.filter((l) => l.conversationKey !== key);
    await user.save();
    res.json({ success: true, data: { locked: false, conversationKey: key } });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}
