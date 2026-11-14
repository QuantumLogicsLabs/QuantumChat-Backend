import { getStorage, newObjectName, safeImageContentType } from '../middleware/upload.js';
import Attachment from '../models/Attachment.js';
import FriendRequest from '../models/FriendRequest.js';
import Group from '../models/Group.js';
import Message from '../models/Message.js';
import User, { KEY_SET_SIZE } from '../models/User.js';
import { createNotification } from '../services/notificationService.js';
import { generateTransliteratedNames } from '../services/transliterationService.js';
import { conversationKey } from '../utils/conversationKey.js';
import { appBaseUrl } from '../utils/mail.js';
import { normalizeNotificationSettings } from '../utils/notificationSettings.js';
import { isEmailLike, normalizePhone, phoneLookupVariants } from '../utils/phone.js';
import { toObjectId } from '../utils/toObjectId.js';

const HEX_64 = /^[0-9a-f]{64}$/i;

const PUBLIC_FIELDS =
  'username displayName statusText bio phone dateOfBirth email publicKeys keyRotatedAt lastLoginAt blockedUsers friends avatarPath avatarMimeType privacy preferredLanguage transliteratedNames emailVerified isSystemUser systemRole verified';


export async function areUsersBlocked(userAId, userBId, aBlockedUsersHint) {
  const aId = toObjectId(userAId);
  const bId = toObjectId(userBId);
  if (!aId || !bId) return true;
  const aBlockedList = aBlockedUsersHint;
  if (aBlockedList) {
    if (aBlockedList.some((id) => String(id) === String(bId))) return true;
    const b = await User.findById(bId).select('blockedUsers');
    if (!b) return true;
    return (b.blockedUsers || []).some((id) => String(id) === String(aId));
  }
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
  try {
    const blockedIds = (req.user.blockedUsers || []).map((id) => id);
    const friendIds = new Set((req.user.friends || []).map((id) => String(id)));

    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 20, 1), 100);
    const cursor = req.query.cursor ? toObjectId(req.query.cursor) : null;
    const q = typeof req.query.q === 'string' ? req.query.q.trim() : '';

    const filter = { _id: { $nin: [req.user._id, ...blockedIds] } };
    if (cursor) filter._id.$gt = cursor;
    if (q) {
      const escaped = q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      filter.$or = [
        { username: { $regex: escaped, $options: 'i' } },
        { displayName: { $regex: escaped, $options: 'i' } },
      ];
    }

    const rows = await User.find(filter)
      .sort({ _id: 1 })
      .limit(limit + 1)
      .select(PUBLIC_FIELDS);

    const hasMore = rows.length > limit;
    const page = hasMore ? rows.slice(0, limit) : rows;

    const data = page
      .filter(
        (u) =>
          friendIds.has(String(u._id)) ||
          (u.privacy?.discoverable || 'everyone') !== 'nobody',
      )
      .map((u) => u.toPublicJSON(req.user._id));

    res.json({
      success: true,
      data,
      meta: {
        hasMore,
        nextCursor: page.length ? String(page[page.length - 1]._id) : null,
      },
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
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
  res.json({ success: true, data: user.toPublicJSON(req.user._id) });
}

export async function updatePrivacy(req, res) {
  try {
     const {
      lastSeen,
      readReceipts,
      onlineStatus,
      onlineStatusVisibleTo,
      whoCanMessage,
      discoverable,
      story,
      storyViewers,
      typingIndicator,
      profileVisibility,
      birthdayVisibility,
      whoCanMention,
      whoCanAddToGroups,
      whoCanInviteViaGroupLink,
      whoCanCreateGroupsWithMe,
      groupMentions,
      screenshotProtection,
      viewStoriesAnonymously,
    } = req.body || {};

    if (lastSeen !== undefined && !['everyone', 'friends', 'nobody'].includes(lastSeen)) {
      return res.status(400).json({ success: false, error: 'Invalid lastSeen privacy setting' });
    }
    if (
      readReceipts !== undefined &&
      typeof readReceipts !== 'boolean' &&
      !['everyone', 'friends', 'nobody'].includes(readReceipts)
    ) {
      return res.status(400).json({ success: false, error: 'Invalid readReceipts privacy setting' });
    }
    if (typingIndicator !== undefined && typeof typingIndicator !== 'boolean') {
      return res.status(400).json({ success: false, error: 'Invalid typingIndicator privacy setting' });
    }
    if (screenshotProtection !== undefined && typeof screenshotProtection !== 'boolean') {
      return res.status(400).json({ success: false, error: 'Invalid screenshotProtection privacy setting' });
    }
    if (viewStoriesAnonymously !== undefined && typeof viewStoriesAnonymously !== 'boolean') {
      return res.status(400).json({ success: false, error: 'Invalid viewStoriesAnonymously privacy setting' });
    }
    if (onlineStatus !== undefined && !['everyone', 'friends', 'selected'].includes(onlineStatus)) {
      return res.status(400).json({ success: false, error: 'Invalid onlineStatus privacy setting' });
    }
    if (onlineStatusVisibleTo !== undefined && !Array.isArray(onlineStatusVisibleTo)) {
      return res.status(400).json({ success: false, error: 'onlineStatusVisibleTo must be an array of user IDs' });
    }
    if (whoCanMessage !== undefined && !['everyone', 'friends', 'friendsOfFriends'].includes(whoCanMessage)) {
      return res.status(400).json({ success: false, error: 'Invalid whoCanMessage privacy setting' });
    }
    if (discoverable !== undefined && !['everyone', 'nobody'].includes(discoverable)) {
      return res.status(400).json({ success: false, error: 'Invalid discoverable privacy setting' });
    }
    if (story !== undefined && !['everyone', 'friends', 'nobody', 'selected'].includes(story)) {
      return res.status(400).json({ success: false, error: 'Invalid story privacy setting' });
    }
    if (storyViewers !== undefined && !Array.isArray(storyViewers)) {
      return res.status(400).json({ success: false, error: 'storyViewers must be an array of user IDs' });
    }
    if (profileVisibility !== undefined && !['everyone', 'friends', 'onlyMe'].includes(profileVisibility)) {
      return res.status(400).json({ success: false, error: 'Invalid profileVisibility privacy setting' });
    }
    if (birthdayVisibility !== undefined && !['everyone', 'friends', 'onlyMe'].includes(birthdayVisibility)) {
      return res.status(400).json({ success: false, error: 'Invalid birthdayVisibility privacy setting' });
    }
    if (whoCanMention !== undefined && !['everyone', 'friends', 'nobody'].includes(whoCanMention)) {
      return res.status(400).json({ success: false, error: 'Invalid whoCanMention privacy setting' });
    }
    if (whoCanAddToGroups !== undefined && !['everyone', 'friends', 'nobody'].includes(whoCanAddToGroups)) {
      return res.status(400).json({ success: false, error: 'Invalid whoCanAddToGroups privacy setting' });
    }
    if (whoCanInviteViaGroupLink !== undefined && !['everyone', 'friends', 'nobody'].includes(whoCanInviteViaGroupLink)) {
      return res.status(400).json({ success: false, error: 'Invalid whoCanInviteViaGroupLink privacy setting' });
    }
    if (whoCanCreateGroupsWithMe !== undefined && !['everyone', 'friends'].includes(whoCanCreateGroupsWithMe)) {
      return res.status(400).json({ success: false, error: 'Invalid whoCanCreateGroupsWithMe privacy setting' });
    }
    if (groupMentions !== undefined && !['everyone', 'adminsOnly', 'nobody'].includes(groupMentions)) {
      return res.status(400).json({ success: false, error: 'Invalid groupMentions privacy setting' });
    }

    const user = req.user;
    applyPrivacyPatch(user, req.body || {});
    user.markModified('privacy');
    await user.save();
    const self = user.toSelfJSON();
    res.json({ success: true, data: self.privacy, user: self });
  } catch (err) {
    const status = err.status || 500;
    res.status(status).json({ success: false, error: err.message });
  }
}

export async function updateProfile(req, res) {
  try {
    const { displayName, statusText, bio, phone, username, privacy, dateOfBirth, timezone, preferredLanguage, transliteratedNames, hasSeenTour } = req.body || {};
    const user = req.user;

    if (preferredLanguage != null) {
      const lang = String(preferredLanguage).trim().toLowerCase();
      if (!/^[a-z]{2,3}(-[a-z0-9]+)?$/i.test(lang) || lang.length > 10) {
        return res.status(400).json({ success: false, error: 'Invalid preferred language format' });
      }
      user.preferredLanguage = lang;
    }

    if (typeof hasSeenTour === 'boolean') {
      user.hasSeenTour = hasSeenTour;
    }

    if (transliteratedNames && typeof transliteratedNames === 'object') {
      const allowedLangs = ['ur', 'ar', 'fa', 'hi', 'zh', 'ru'];
      user.transliteratedNames = user.transliteratedNames || {};
      for (const lang of allowedLangs) {
        if (transliteratedNames[lang] !== undefined) {
          user.transliteratedNames[lang] = String(transliteratedNames[lang]).trim().slice(0, 60);
        }
      }
      user.markModified('transliteratedNames');
    }

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
      const trimmedDisplay = displayName.trim();
      const changed = trimmedDisplay !== user.displayName;
      user.displayName = trimmedDisplay;

      if (changed && !transliteratedNames) {
        try {
          const generated = await generateTransliteratedNames(user.displayName || user.username);
          user.transliteratedNames = {
            ...(user.transliteratedNames?.toObject?.() || user.transliteratedNames || {}),
            ...generated,
          };
          user.markModified('transliteratedNames');
        } catch {
          // Graceful fallback
        }
      }
    }
    if (bio != null) {
      if (typeof bio !== 'string' || bio.length > 300) {
        return res.status(400).json({ success: false, error: 'Bio must be under 300 characters' });
      }
      user.bio = bio.trim();
    }
    // Custom status line. Never trust the client's length check: reject > 100
    // chars server-side. An empty/whitespace-only value clears the status.
    if (statusText != null) {
      if (typeof statusText !== 'string') {
        return res.status(400).json({ success: false, error: 'Status must be text' });
      }
      const trimmedStatus = statusText.trim();
      if (trimmedStatus.length > 100) {
        return res.status(400).json({ success: false, error: 'Status must be under 100 characters' });
      }
      user.statusText = trimmedStatus;
    }
    if (phone != null) {
      if (typeof phone !== 'string' || phone.length > 32) {
        return res.status(400).json({ success: false, error: 'Phone must be under 32 characters' });
      }
      const normalized = normalizePhone(phone);
      if (phone.trim() && (!normalized || normalized.replace(/\D/g, '').length < 7)) {
        return res.status(400).json({ success: false, error: 'Enter a valid phone number' });
      }
      user.phone = normalized;
    }
    if (dateOfBirth != null) {
      if (dateOfBirth === '') {
        user.dateOfBirth = null; // explicit clear
      } else {
        const parsed = new Date(dateOfBirth);
        if (Number.isNaN(parsed.getTime())) {
          return res.status(400).json({ success: false, error: 'Enter a valid date of birth' });
        }
        if (parsed > new Date()) {
          return res.status(400).json({ success: false, error: 'Date of birth cannot be in the future' });
        }
        // Reset the "already notified this year" guard whenever the date changes,
        // so a corrected birthday isn't silently skipped for the rest of the year.
        user.lastBirthdayNotifiedYear = null;
        user.dateOfBirth = parsed;
      }
    }
     if (timezone != null) {
      const tz = String(timezone).trim().slice(0, 64);
      if (tz) {
        try {
          Intl.DateTimeFormat(undefined, { timeZone: tz }); // throws on invalid IANA name
          if (tz !== user.timezone) {
            // Same reasoning as the dateOfBirth reset above — a timezone
            // change shifts when "local midnight" actually falls, so don't
            // let a stale guard from the old zone skip this year's notice.
            user.lastBirthdayNotifiedYear = null;
          }
          user.timezone = tz;
        } catch {
          return res.status(400).json({ success: false, error: 'Invalid timezone' });
        }
      }
    }
    if (privacy && typeof privacy === 'object') {
      applyPrivacyPatch(user, privacy);
    }

    await user.save();

    // Real-time status propagation. This is deliberately separate from presence
    // events and never touches online/offline state. Emit only when the client
    // actually sent a status value, to the user's own devices (multi-device
    // sync) and to friends (who see it near the name / in the profile).
    // Non-friends pick it up on their next profile/user-list fetch.
    if (statusText != null) {
      const io = req.app.get('io');
      if (io) {
        const payload = { userId: String(user._id), statusText: user.statusText || '' };
        const targets = new Set([String(user._id), ...(user.friends || []).map((f) => String(f._id || f))]);
        for (const t of targets) io.to(t).emit('user:status', payload);
      }
    }

    res.json({ success: true, data: user.toSelfJSON() });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

function applyPrivacyPatch(user, privacy) {
  if (!privacy || typeof privacy !== 'object') return;
  user.privacy = user.privacy || {};

  const lastSeenOk = ['everyone', 'friends', 'nobody'];
  const readOk = ['everyone', 'friends', 'nobody'];
  const onlineStatusOk = ['everyone', 'friends', 'selected'];
  const whoOk = ['everyone', 'friends', 'friendsOfFriends'];
  const storyOk = ['everyone', 'friends', 'nobody', 'selected']; 
  const discoverOk = ['everyone', 'nobody'];
  const profileVisibilityOk = ['everyone', 'friends', 'onlyMe'];
  const birthdayVisibilityOk = ['everyone', 'friends', 'onlyMe'];
  const whoCanMentionOk = ['everyone', 'friends', 'nobody'];
  const whoCanAddToGroupsOk = ['everyone', 'friends', 'nobody'];
  const whoCanInviteViaGroupLinkOk = ['everyone', 'friends', 'nobody'];
  const whoCanCreateGroupsWithMeOk = ['everyone', 'friends'];
  const groupMentionsOk = ['everyone', 'adminsOnly', 'nobody'];

  if (lastSeenOk.includes(privacy.lastSeen)) {
    user.privacy.lastSeen = privacy.lastSeen;
  }

  if (typeof privacy.readReceipts === 'boolean') {
    user.privacy.readReceipts = privacy.readReceipts ? 'everyone' : 'nobody';
  } else if (readOk.includes(privacy.readReceipts)) {
    user.privacy.readReceipts = privacy.readReceipts;
  }

  if (typeof privacy.typingIndicator === 'boolean') {
    user.privacy.typingIndicator = privacy.typingIndicator;
  }

  if (typeof privacy.screenshotProtection === 'boolean') {
    user.privacy.screenshotProtection = privacy.screenshotProtection;
  }

  if (typeof privacy.viewStoriesAnonymously === 'boolean') {
    user.privacy.viewStoriesAnonymously = privacy.viewStoriesAnonymously;
  }

  if (onlineStatusOk.includes(privacy.onlineStatus)) {
    user.privacy.onlineStatus = privacy.onlineStatus;
    // Presence still broadcasts; consumers should honor onlineStatus / visibleTo.
    user.privacy.online = 'everyone';
  } else if (privacy.online === 'everyone' || privacy.online === 'nobody') {
    user.privacy.online = privacy.online;
    if (!user.privacy.onlineStatus) {
      user.privacy.onlineStatus = privacy.online === 'nobody' ? 'selected' : 'everyone';
    }
  }

  if (Array.isArray(privacy.onlineStatusVisibleTo)) {
    const friendSet = new Set((user.friends || []).map((id) => String(id)));
    const next = [];
    for (const raw of privacy.onlineStatusVisibleTo) {
      const id = toObjectId(raw);
      if (id && friendSet.has(String(id))) next.push(id);
    }
    user.privacy.onlineStatusVisibleTo = next;
  }

  if (whoOk.includes(privacy.whoCanMessage)) {
    user.privacy.whoCanMessage = privacy.whoCanMessage;
  }
  if (discoverOk.includes(privacy.discoverable)) {
    user.privacy.discoverable = privacy.discoverable;
  }
  // --- Story privacy ---
  if (storyOk.includes(privacy.story)) {
    user.privacy.story = privacy.story;
  }
  if (Array.isArray(privacy.storyViewers)) {
    const friendSet = new Set((user.friends || []).map((id) => String(id)));
    const next = [];
    for (const raw of privacy.storyViewers) {
      const id = toObjectId(raw);
      if (id && friendSet.has(String(id))) next.push(id);
    }
    user.privacy.storyViewers = next;
  }
  if (profileVisibilityOk.includes(privacy.profileVisibility)) {
    user.privacy.profileVisibility = privacy.profileVisibility;
  }
  if (birthdayVisibilityOk.includes(privacy.birthdayVisibility)) {
    user.privacy.birthdayVisibility = privacy.birthdayVisibility;
  }
  if (whoCanMentionOk.includes(privacy.whoCanMention)) {
    user.privacy.whoCanMention = privacy.whoCanMention;
  }
  if (whoCanAddToGroupsOk.includes(privacy.whoCanAddToGroups)) {
    user.privacy.whoCanAddToGroups = privacy.whoCanAddToGroups;
  }
  if (whoCanInviteViaGroupLinkOk.includes(privacy.whoCanInviteViaGroupLink)) {
    user.privacy.whoCanInviteViaGroupLink = privacy.whoCanInviteViaGroupLink;
  }
  if (whoCanCreateGroupsWithMeOk.includes(privacy.whoCanCreateGroupsWithMe)) {
    user.privacy.whoCanCreateGroupsWithMe = privacy.whoCanCreateGroupsWithMe;
  }
  if (groupMentionsOk.includes(privacy.groupMentions)) {
    user.privacy.groupMentions = privacy.groupMentions;
  }
}

export async function getNotificationSettings(req, res) {
  try {
    res.json({ success: true, data: normalizeNotificationSettings(req.user.notificationSettings) });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

export async function updateNotificationSettings(req, res) {
  try {
    const settings = req.body || {};
    const user = req.user;
    // Ensure a real nested subdoc exists so Mongoose change tracking works.
    if (!user.notificationSettings || typeof user.notificationSettings !== 'object') {
      user.notificationSettings = {};
    }

    const enums = {
      messageNotifications: ['all', 'direct_only', 'all_except_reactions'],
      statusNotifications: ['all', 'selected', 'off'],
      messagePreview: ['full', 'sender_only', 'hidden'],
      vibration: ['on', 'off', 'custom'],
      groupNotifications: ['all', 'mentions_only', 'important_only', 'off'],
      badgeCount: ['show', 'hidden'],
      priority: ['high', 'normal', 'silent'],
    };

    for (const [key, allowed] of Object.entries(enums)) {
      if (settings[key] != null && allowed.includes(settings[key])) {
        user.notificationSettings[key] = settings[key];
      }
    }

    if (Array.isArray(settings.statusNotificationsSelectedFriends)) {
      const friendSet = new Set((user.friends || []).map((id) => String(id)));
      // Mongoose auto-casts valid ObjectId strings assigned to a
      // schema-typed array, so no manual ObjectId conversion is needed here.
      user.notificationSettings.statusNotificationsSelectedFriends = settings.statusNotificationsSelectedFriends
        .map((id) => String(id))
        .filter((id) => friendSet.has(id));
    }

    if (typeof settings.soundEnabled === 'boolean') {
      user.notificationSettings.soundEnabled = settings.soundEnabled;
    }
    if (typeof settings.birthdayReminders === 'boolean') {
      user.notificationSettings.birthdayReminders = settings.birthdayReminders;
    }
    if (typeof settings.liveNotifications === 'boolean') {
      user.notificationSettings.liveNotifications = settings.liveNotifications;
    }
    if (typeof settings.soundVolume === 'number' && settings.soundVolume >= 0 && settings.soundVolume <= 100) {
      user.notificationSettings.soundVolume = settings.soundVolume;
    }

    if (settings.doNotDisturb && typeof settings.doNotDisturb === 'object') {
      const dnd = {
        ...(user.notificationSettings.doNotDisturb?.toObject?.() ||
          user.notificationSettings.doNotDisturb ||
          {}),
      };
      if (typeof settings.doNotDisturb.enabled === 'boolean') dnd.enabled = settings.doNotDisturb.enabled;
      if (typeof settings.doNotDisturb.startTime === 'string') dnd.startTime = settings.doNotDisturb.startTime;
      if (typeof settings.doNotDisturb.endTime === 'string') dnd.endTime = settings.doNotDisturb.endTime;
      if (Array.isArray(settings.doNotDisturb.allowedContacts)) {
        dnd.allowedContacts = settings.doNotDisturb.allowedContacts;
      }
      user.notificationSettings.doNotDisturb = dnd;
    }

    if (settings.callNotifications && typeof settings.callNotifications === 'object') {
      const call = {
        ...(user.notificationSettings.callNotifications?.toObject?.() ||
          user.notificationSettings.callNotifications ||
          {}),
      };
      const c = settings.callNotifications;
      if (typeof c.voiceCallEnabled === 'boolean') call.voiceCallEnabled = c.voiceCallEnabled;
      if (typeof c.videoCallEnabled === 'boolean') call.videoCallEnabled = c.videoCallEnabled;
      if (typeof c.vibrateOnCall === 'boolean') call.vibrateOnCall = c.vibrateOnCall;
      if (typeof c.missedCallReminders === 'boolean') call.missedCallReminders = c.missedCallReminders;
      user.notificationSettings.callNotifications = call;
    }

    if (settings.mediaSettings && typeof settings.mediaSettings === 'object') {
      const media = {
        ...(user.notificationSettings.mediaSettings?.toObject?.() ||
          user.notificationSettings.mediaSettings ||
          {}),
      };
      const m = settings.mediaSettings;
      if (typeof m.autoDownloadImages === 'boolean') media.autoDownloadImages = m.autoDownloadImages;
      if (typeof m.autoDownloadVideos === 'boolean') media.autoDownloadVideos = m.autoDownloadVideos;
      if (typeof m.wifiOnly === 'boolean') media.wifiOnly = m.wifiOnly;
      user.notificationSettings.mediaSettings = media;
    }

    if (settings.webNotifications && typeof settings.webNotifications === 'object') {
      const web = {
        ...(user.notificationSettings.webNotifications?.toObject?.() ||
          user.notificationSettings.webNotifications ||
          {}),
      };
      const w = settings.webNotifications;
      if (typeof w.enabled === 'boolean') web.enabled = w.enabled;
      if (typeof w.soundOnWeb === 'boolean') web.soundOnWeb = w.soundOnWeb;
      if (typeof w.syncReadAcrossDevices === 'boolean') web.syncReadAcrossDevices = w.syncReadAcrossDevices;
      user.notificationSettings.webNotifications = web;
    }

    user.markModified('notificationSettings');
    await user.save();
    res.json({
      success: true,
      data: normalizeNotificationSettings(user.notificationSettings),
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}
const MUTE_DURATIONS = {
  '8h': 8 * 60 * 60 * 1000,
  '1w': 7 * 24 * 60 * 60 * 1000,
  always: null,
};

export async function muteChat(req, res) {
  try {
    const { peerId, groupId, duration } = req.body || {};
    if (!MUTE_DURATIONS.hasOwnProperty(duration)) {
      return res.status(400).json({ success: false, error: 'duration must be one of: 8h, 1w, always' });
    }
    if (!peerId && !groupId) {
      return res.status(400).json({ success: false, error: 'peerId or groupId is required' });
    }

    const key = conversationKey(
      groupId ? { group: groupId } : { from: req.user._id, to: peerId }
    );
    const ms = MUTE_DURATIONS[duration];
    const expiresAt = ms == null ? null : new Date(Date.now() + ms);

    const user = req.user;
    user.mutedChats = (user.mutedChats || []).filter((m) => m.conversationKey !== key);
    user.mutedChats.push({ conversationKey: key, expiresAt });
    await user.save();

    res.json({ success: true, data: user.toSelfJSON() });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

export async function unmuteChat(req, res) {
  try {
    const { peerId, groupId } = req.body || {};
    if (!peerId && !groupId) {
      return res.status(400).json({ success: false, error: 'peerId or groupId is required' });
    }
    const key = conversationKey(
      groupId ? { group: groupId } : { from: req.user._id, to: peerId }
    );

    const user = req.user;
    user.mutedChats = (user.mutedChats || []).filter((m) => m.conversationKey !== key);
    await user.save();

    res.json({ success: true, data: user.toSelfJSON() });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

/**
 * Clear a conversation *for the calling user only*. This never deletes shared
 * message documents — doing so would destroy the peer's or other group members'
 * history and could not be safely scoped for groups. Instead we record a
 * per-user watermark (clearedConversations) so this user's own views (on every
 * device) hide messages at or before `clearedAt` for this one conversation.
 * The conversation, contact, and group all stay in the list; sending new
 * messages afterwards works normally. E2E ciphertext is untouched.
 */
const CLEAR_SCOPES = ['all', 'photo', 'video', 'voice', 'document', 'text'];

export async function clearConversation(req, res) {
  try {
    const { peerId, groupId, scopes: scopesRaw } = req.body || {};
    if (!peerId && !groupId) {
      return res.status(400).json({ success: false, error: 'peerId or groupId is required' });
    }
    if (peerId && groupId) {
      return res.status(400).json({ success: false, error: 'Provide either peerId or groupId, not both' });
    }

    const scopes = Array.isArray(scopesRaw) && scopesRaw.length
      ? [...new Set(scopesRaw.map(String))]
      : ['all'];
    if (scopes.some((s) => !CLEAR_SCOPES.includes(s))) {
      return res.status(400).json({ success: false, error: 'Invalid clear scope' });
    }

    // For a group clear, confirm the caller is actually a member before we
    // record a watermark. This is a per-user, view-only action — it can never
    // delete the group or affect other members — but we still gate it so a
    // non-member cannot set state against a group they cannot access.
    if (groupId) {
      const gid = toObjectId(groupId);
      if (!gid) return res.status(400).json({ success: false, error: 'Invalid group id' });
      const group = await Group.findById(gid).select('members');
      if (!group) return res.status(404).json({ success: false, error: 'Group not found' });
      if (!group.isMember(req.user._id)) {
        return res.status(403).json({ success: false, error: 'Not a group member' });
      }
    } else {
      const pid = toObjectId(peerId);
      if (!pid) return res.status(400).json({ success: false, error: 'Invalid user id' });
    }

    const key = conversationKey(
      groupId ? { group: groupId } : { from: req.user._id, to: peerId }
    );
    const clearedAt = new Date();

    const user = req.user;
    const already = user.clearedConversations || [];
    // 'all' supersedes every other scope for this conversation — once
    // everything is cleared, per-category watermarks for the same key are
    // redundant and would only complicate later reads.
    let nextList;
    if (scopes.includes('all')) {
      nextList = [
        ...already.filter((c) => c.conversationKey !== key),
        { conversationKey: key, scope: 'all', clearedAt },
      ];
    } else {
      nextList = [
        ...already.filter((c) => {
          if (c.conversationKey !== key) return true;
          // Entries with no `scope` field at all predate this feature and
          // would otherwise be silently read as an 'all' clear forever
          // (via the `c.scope || 'all'` fallback on the read side). Always
          // drop them here — a scoped clear request replaces that stale,
          // ambiguous watermark with the specific scope(s) actually asked
          // for now. Legitimate scoped/'all' entries created *after* this
          // feature shipped always have an explicit scope and are left
          // alone unless the new request targets that same scope.
          if (c.scope == null) return false;
          return !scopes.includes(c.scope);
        }),
        ...scopes.map((scope) => ({ conversationKey: key, scope, clearedAt })),
      ];
    }
    user.clearedConversations = nextList;
    await user.save();

    // Sync the clear across the user's own devices so a second logged-in
    // session stops showing the now-hidden messages. Scoped to the caller's
    // own room only — peers and other group members are never notified.
    const io = req.app.get('io');
    if (io) {
      io.to(String(user._id)).emit('chat:cleared', {
        conversationKey: key,
        peerId: peerId ? String(peerId) : null,
        groupId: groupId ? String(groupId) : null,
        scopes,
        clearedAt,
      });
    }

    res.json({ success: true, data: user.toSelfJSON() });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

/**
 * Undo a recent "clear chat" by restoring the previous watermark entries for
 * this conversation. The client sends the snapshot taken right before clear.
 * Empty restoreEntries means "no clear watermark for this chat" (full undo).
 */
export async function undoClearConversation(req, res) {
  try {
    const { peerId, groupId, restoreEntries: restoreRaw } = req.body || {};
    if (!peerId && !groupId) {
      return res.status(400).json({ success: false, error: 'peerId or groupId is required' });
    }
    if (peerId && groupId) {
      return res.status(400).json({ success: false, error: 'Provide either peerId or groupId, not both' });
    }

    if (groupId) {
      const gid = toObjectId(groupId);
      if (!gid) return res.status(400).json({ success: false, error: 'Invalid group id' });
      const group = await Group.findById(gid).select('members');
      if (!group) return res.status(404).json({ success: false, error: 'Group not found' });
      if (!group.isMember(req.user._id)) {
        return res.status(403).json({ success: false, error: 'Not a group member' });
      }
    } else {
      const pid = toObjectId(peerId);
      if (!pid) return res.status(400).json({ success: false, error: 'Invalid user id' });
    }

    const key = conversationKey(
      groupId ? { group: groupId } : { from: req.user._id, to: peerId }
    );

    const restoreEntries = Array.isArray(restoreRaw) ? restoreRaw : [];
    const normalized = [];
    for (const entry of restoreEntries) {
      if (!entry || typeof entry !== 'object') continue;
      // Only accept entries for this conversation — never let a client
      // rewrite watermarks for unrelated chats.
      if (String(entry.conversationKey || '') !== key) continue;
      const scope = String(entry.scope || 'all');
      if (!CLEAR_SCOPES.includes(scope)) continue;
      const clearedAt = entry.clearedAt ? new Date(entry.clearedAt) : null;
      if (!clearedAt || Number.isNaN(clearedAt.getTime())) continue;
      normalized.push({ conversationKey: key, scope, clearedAt });
    }

    const user = req.user;
    const already = user.clearedConversations || [];
    user.clearedConversations = [
      ...already.filter((c) => c.conversationKey !== key),
      ...normalized,
    ];
    await user.save();

    const io = req.app.get('io');
    if (io) {
      io.to(String(user._id)).emit('chat:clear-undone', {
        conversationKey: key,
        peerId: peerId ? String(peerId) : null,
        groupId: groupId ? String(groupId) : null,
      });
    }

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
    // Exclude self / friends / blocked in the query BEFORE limiting so users
    // with large friend lists still get a full page of discoverable people.
    const blockedIds = (req.user.blockedUsers || [])
      .map((id) => toObjectId(id))
      .filter(Boolean);
    const friendIds = (req.user.friends || [])
      .map((id) => toObjectId(id))
      .filter(Boolean);
    const excludeIds = [req.user._id, ...blockedIds, ...friendIds];
    const q = typeof req.query.q === 'string' ? req.query.q.trim() : '';
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 200, 1), 500);
    const cursor = req.query.cursor ? toObjectId(req.query.cursor) : null;

    const filter = {
      _id: { $nin: excludeIds },
      isSystemUser: { $ne: true },
      // Missing privacy.discoverable still matches (treated as "everyone").
      'privacy.discoverable': { $nin: ['nobody'] },
    };
    if (cursor) {
      filter._id = { $nin: excludeIds, $gt: cursor };
    }
    if (q) {
      const escaped = q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      filter.$or = [
        { username: { $regex: escaped, $options: 'i' } },
        { displayName: { $regex: escaped, $options: 'i' } },
      ];
    }

    const rows = await User.find(filter)
      .sort({ _id: 1 })
      .limit(limit + 1)
      .select(PUBLIC_FIELDS);
    const hasMore = rows.length > limit;
    const candidates = hasMore ? rows.slice(0, limit) : rows;
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
        ...u.toPublicJSON(req.user._id),
        requestStatus: info?.status || 'none',
        requestId: info?.requestId || null,
      };
    });

    res.json({
      success: true,
      data,
      meta: {
        hasMore,
        nextCursor: candidates.length
          ? String(candidates[candidates.length - 1]._id)
          : null,
      },
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

/**
 * Exact lookup by email or phone for Find Friends.
 * Never returns the contact itself — only public profile + request status.
 */
export async function lookupContact(req, res) {
  try {
    const emailRaw = typeof req.query.email === 'string' ? req.query.email.trim().toLowerCase() : '';
    const phoneRaw = typeof req.query.phone === 'string' ? req.query.phone.trim() : '';

    if (!emailRaw && !phoneRaw) {
      return res.status(400).json({
        success: false,
        error: 'Provide an email or phone number',
      });
    }
    if (emailRaw && phoneRaw) {
      return res.status(400).json({
        success: false,
        error: 'Search by email or phone, not both',
      });
    }

    let target = null;

    if (emailRaw) {
      if (!isEmailLike(emailRaw)) {
        return res.status(400).json({ success: false, error: 'Enter a valid email address' });
      }
      target = await User.findOne({
        email: emailRaw,
        emailVerified: true,
        isSystemUser: { $ne: true },
      }).select(PUBLIC_FIELDS);
    } else {
      const variants = phoneLookupVariants(phoneRaw);
      if (!variants.length || variants[0].replace(/\D/g, '').length < 7) {
        return res.status(400).json({ success: false, error: 'Enter a valid phone number' });
      }
      target = await User.findOne({
        phone: { $in: variants },
        isSystemUser: { $ne: true },
      }).select(PUBLIC_FIELDS);
    }

    if (!target || String(target._id) === String(req.user._id)) {
      return res.json({ success: true, data: null });
    }

    const blocked = await areUsersBlocked(req.user._id, target._id);
    if (blocked) {
      return res.json({ success: true, data: null });
    }

    const friendIds = new Set((req.user.friends || []).map((id) => String(id)));
    const alreadyFriend = friendIds.has(String(target._id));

    let requestStatus = alreadyFriend ? 'friends' : 'none';
    let requestId = null;

    if (!alreadyFriend) {
      const pending = await FriendRequest.findOne({
        status: 'pending',
        $or: [
          { from: req.user._id, to: target._id },
          { to: req.user._id, from: target._id },
        ],
      });
      if (pending) {
        if (String(pending.from) === String(req.user._id)) {
          requestStatus = 'pending_sent';
        } else {
          requestStatus = 'pending_received';
        }
        requestId = pending._id;
      }
    }

    res.json({
      success: true,
      data: {
        ...target.toPublicJSON(),
        requestStatus,
        requestId,
        matchedBy: emailRaw ? 'email' : 'phone',
      },
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

/** Accepted friends for the Friends tab. */
export async function listFriends(req, res) {
  try {
    const friendIds = req.user.friends || [];
    if (!friendIds.length) {
      return res.json({ success: true, data: [] });
    }

    const blockedIds = new Set((req.user.blockedUsers || []).map((id) => String(id)));
    const users = await User.find({
      _id: { $in: friendIds },
      isSystemUser: { $ne: true },
    }).select(PUBLIC_FIELDS);

    const byId = new Map(users.map((u) => [String(u._id), u]));
    const data = friendIds
      .map((id) => byId.get(String(id)))
      .filter(Boolean)
      .filter((u) => !blockedIds.has(String(u._id)))
      .map((u) => u.toPublicJSON(req.user._id));

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
    friend: toUser.toPublicJSON(request.from),
  });
  io?.to(String(request.to)).emit('friend:request:accepted', {
    id: request._id,
    friend: fromUser.toPublicJSON(request.to),
  });
  // Only the original requester gets notified here — request.to is the
  // person who just took the accept action, they don't need telling about
  // their own action.
  createNotification({
    recipient: request.from,
    actor: request.to,
    type: 'FRIEND_REQUEST_ACCEPTED',
    entityType: 'friend_request',
    entityId: request._id,
    io,
  }).catch(() => {});
}

export async function sendFriendRequest(req, res) {
  try {
    const { to } = req.body || {};
    const targetId = toObjectId(to);
    if (!targetId || targetId.equals(req.user._id)) {
      return res.status(400).json({ success: false, error: 'Invalid user id' });
    }

    const target = await User.findById(targetId).select('_id isSystemUser');
    if (!target) return res.status(404).json({ success: false, error: 'User not found' });
    if (target.isSystemUser) {
      return res.status(400).json({ success: false, error: 'Cannot send a friend request to this account' });
    }
     if (req.user.moderation?.status === 'restricted') {
      return res.status(403).json({
        success: false,
        error: 'Your account is currently restricted from sending new friend requests',
      });
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
        const me = await User.findById(req.user._id);
        return res.json({
          success: true,
          data: { id: existing._id, status: 'accepted', me: me.toSelfJSON() },
        });
      }
      return res.status(409).json({ success: false, error: 'Friend request already sent' });
    }

    const request = await FriendRequest.create({ from: req.user._id, to: target._id, status: 'pending' });

    const io = req.app.get('io');
    io?.to(String(target._id)).emit('friend:request:new', {
      id: request._id,
      from: req.user.toPublicJSON(),
    });

    createNotification({
      recipient: target._id,
      actor: req.user._id,
      type: 'FRIEND_REQUEST',
      entityType: 'friend_request',
      entityId: request._id,
      io,
    }).catch(() => {});

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
      // Include `moderation` on the populated sender only — it's never
      // added to the shared PUBLIC_FIELDS constant, so no other endpoint
      // that reuses that string starts leaking report counts.
      FriendRequest.find({ to: req.user._id, status: 'pending' }).populate('from', `${PUBLIC_FIELDS} moderation`),
      FriendRequest.find({ from: req.user._id, status: 'pending' }).populate('to', PUBLIC_FIELDS),
    ]);
    res.json({
      success: true,
      data: {
        incoming: incoming.map((r) => ({
          id: r._id,
          user: r.from.toPublicJSON(),
          createdAt: r.createdAt,
          // null below the 7-report threshold; otherwise
          // { reportedByMultiple: true, commonReason } — never a count,
          // never anything about who reported.
          moderationWarning: r.from.getModerationSafetyWarning?.() || null,
        })),
        outgoing: outgoing.map((r) => ({ id: r._id, user: r.to.toPublicJSON(), createdAt: r.createdAt })),
      },
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

export async function acceptFriendRequest(req, res) {
  try {
    const requestId = toObjectId(req.params.id);
    if (!requestId) {
      return res.status(400).json({ success: false, error: 'Invalid request id' });
    }
    const request = await FriendRequest.findById(requestId);
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
    const requestId = toObjectId(req.params.id);
    if (!requestId) {
      return res.status(400).json({ success: false, error: 'Invalid request id' });
    }
    const request = await FriendRequest.findById(requestId);
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
    const requestId = toObjectId(req.params.id);
    if (!requestId) {
      return res.status(400).json({ success: false, error: 'Invalid request id' });
    }
    const request = await FriendRequest.findById(requestId);
    if (!request || request.status !== 'pending') {
      return res.status(404).json({ success: false, error: 'Friend request not found' });
    }
    if (String(request.from) !== String(req.user._id)) {
      return res.status(403).json({ success: false, error: 'Not authorized to cancel this request' });
    }
    await request.deleteOne();
    res.json({ success: true, data: { id: requestId, cancelled: true } });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

export async function removeFriend(req, res) {
  try {
    const friendId = toObjectId(req.params.id);
    if (!friendId || friendId.equals(req.user._id)) {
      return res.status(400).json({ success: false, error: 'Invalid user id' });
    }

    const isFriend = (req.user.friends || []).some((f) => String(f) === String(friendId));
    if (!isFriend) {
      return res.status(404).json({ success: false, error: 'Not currently friends with this user' });
    }

    await Promise.all([
      User.updateOne({ _id: req.user._id }, { $pull: { friends: friendId } }),
      User.updateOne({ _id: friendId }, { $pull: { friends: req.user._id } }),
    ]);

    const io = req.app.get('io');
    io?.to(String(friendId)).emit('friend:removed', { by: String(req.user._id) });
    const me = await User.findById(req.user._id);
    res.json({ success: true, data: { id: friendId, removed: true, me: me.toSelfJSON() } });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

export async function updateLanguage(req, res) {
  try {
    const { language } = req.body || {};
    const lang = String(language || '').trim().toLowerCase();
    if (!lang || !/^[a-z]{2,3}(-[a-z0-9]+)?$/i.test(lang) || lang.length > 10) {
      return res.status(400).json({ success: false, error: 'Invalid language format' });
    }
    req.user.preferredLanguage = lang;
    await req.user.save();
    res.json({ success: true, data: req.user.toSelfJSON() });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}

/** My invite link plus the list of people who joined using it. */
export async function getMyReferrals(req, res) {
  try {
    const referredUsers = await User.find({ referredBy: req.user._id })
      .select('username displayName avatarPath createdAt')
      .sort({ createdAt: -1 });

    res.json({
      success: true,
      data: {
        referralCode: req.user.referralCode,
        referralLink: `${appBaseUrl()}/register?ref=${req.user.referralCode}`,
        invitedCount: referredUsers.length,
        invitedUsers: referredUsers.map((u) => ({
          id: u._id,
          username: u.username,
          displayName: u.displayName || '',
          hasAvatar: Boolean(u.avatarPath),
          joinedAt: u.createdAt,
        })),
      },
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
}