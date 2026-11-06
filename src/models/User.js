import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import mongoose from 'mongoose';
import { normalizeNotificationSettings } from '../utils/notificationSettings.js';
const HEX_64 = /^[0-9a-f]{64}$/i;
export const KEY_SET_SIZE = 5;

const privacySchema = new mongoose.Schema(
  {
    lastSeen: {
      type: String,
      enum: ['everyone', 'friends', 'nobody'],
      default: 'everyone',
    },
    /** Legacy presence gate used by sockets (`everyone` | `nobody`). */
    online: { type: String, enum: ['everyone', 'nobody'], default: 'everyone' },
    onlineStatus: {
      type: String,
      enum: ['everyone', 'friends', 'selected', 'no one '],
      default: 'everyone',
    },
    onlineStatusVisibleTo: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    /** Boolean (legacy) or `everyone` | `friends` | `nobody`. */
    readReceipts: { type: mongoose.Schema.Types.Mixed, default: 'everyone' },
    /** When false, this user does not broadcast typing indicators to peers. */
    typingIndicator: { type: Boolean, default: true },
    whoCanMessage: {
      type: String,
      enum: ['everyone', 'friends', 'friendsOfFriends'],
      default: 'everyone',
    },
    discoverable: {
      type: String,
      enum: ['everyone', 'nobody'],
      default: 'everyone',
    },
    story: {
      type: String,
      enum: ['everyone', 'friends', 'nobody', 'selected'],
      default: 'everyone',
    },
    storyViewers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    profileVisibility: {
      type: String,
      enum: ['everyone', 'friends', 'onlyMe'],
      default: 'everyone',
    },
    birthdayVisibility: {
      type: String,
      enum: ['everyone', 'friends', 'onlyMe'],
      default: 'everyone',
    },
    whoCanMention: {
      type: String,
      enum: ['everyone', 'friends', 'nobody'],
      default: 'everyone',
    },
    whoCanAddToGroups: {
      type: String,
      enum: ['everyone', 'friends', 'nobody'],
      default: 'everyone',
    },
    whoCanInviteViaGroupLink: {
      type: String,
      enum: ['everyone', 'friends', 'nobody'],
      default: 'everyone',
    },
    whoCanCreateGroupsWithMe: {
      type: String,
      enum: ['everyone', 'friends'],
      default: 'everyone',
    },
    groupMentions: {
      type: String,
      enum: ['everyone', 'adminsOnly', 'nobody'],
      default: 'everyone',
    },
    /**
     * When true, other users cannot screenshot / screen-record this user's
     * chats and profile on their device (strongest on mobile).
     */
    screenshotProtection: { type: Boolean, default: false },
    /**
     * When true: (a) this user's story views are recorded anonymously to
     * everyone else, and (b) as the reciprocal trade-off, this user can no
     * longer see who viewed their OWN stories — enforced server-side in
     * storyController.getStoryViewers, never just hidden client-side.
     */
    viewStoriesAnonymously: { type: Boolean, default: false },
  },
  { _id: false }
);
const notificationSettingsSchema = new mongoose.Schema(
  {
    messageNotifications: {
      type: String,
      enum: ['all', 'direct_only', 'all_except_reactions'],
      default: 'all',
    },
    statusNotifications: {
      type: String,
      enum: ['all', 'selected', 'off'],
      default: 'all',
    },
    // Friend ids permitted to notify this user about their story/status
    // updates — only meaningful when statusNotifications === 'selected'.
    statusNotificationsSelectedFriends: [
      { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    ],
    soundEnabled: { type: Boolean, default: true },
    soundVolume: { type: Number, min: 0, max: 100, default: 80 },
    messagePreview: {
      type: String,
      enum: ['full', 'sender_only', 'hidden'],
      default: 'full',
    },
    vibration: {
      type: String,
      enum: ['on', 'off', 'custom'],
      default: 'on',
    },
     /** Whether this user wants a reminder 5 minutes before a friend's birthday begins. */
    birthdayReminders: { type: Boolean, default: true },
    /** Notify when a friend (or a group this user is in) goes live. */
    liveNotifications: { type: Boolean, default: true },
    doNotDisturb: {
      enabled: { type: Boolean, default: false },
      startTime: { type: String, default: '22:00' },
      endTime: { type: String, default: '07:00' },
      allowedContacts: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    },
    groupNotifications: {
      type: String,
      enum: ['all', 'mentions_only', 'important_only', 'off'],
      default: 'all',
    },
    callNotifications: {
      voiceCallEnabled: { type: Boolean, default: true },
      videoCallEnabled: { type: Boolean, default: true },
      vibrateOnCall: { type: Boolean, default: true },
      missedCallReminders: { type: Boolean, default: true },
    },
    badgeCount: {
      type: String,
      enum: ['show', 'hidden'],
      default: 'show',
    },
    webNotifications: {
      enabled: { type: Boolean, default: true },
      soundOnWeb: { type: Boolean, default: true },
      syncReadAcrossDevices: { type: Boolean, default: true },
    },
    // Was never declared here despite being read/written throughout the
    // controller and frontend — Mongoose's default strict mode silently
    // drops any field not declared in the schema on save, so every
    // auto-download toggle appeared to work in the UI for a moment but
    // was never actually persisted.
    mediaSettings: {
      autoDownloadImages: { type: Boolean, default: true },
      autoDownloadVideos: { type: Boolean, default: false },
      wifiOnly: { type: Boolean, default: true },
    },
    priority: {
      type: String,
      enum: ['high', 'normal', 'silent'],
      default: 'normal',
    },
  },
  { _id: false }
);
const mutedChatSchema = new mongoose.Schema(
  {
    conversationKey: { type: String, required: true },
    expiresAt: { type: Date, default: null }, // null = muted forever ("Always")
  },
  { _id: false }
);
// User-defined chat folders ("Work", "Family"), shown beside the All/Unread/
// Groups filters. Purely an organising aid for the owner — never exposed to
// anyone else. Keys use the client's per-viewer format (`dm:<peerId>` /
// `group:<groupId>`), which is unambiguous because the list is per-user.
const chatFolderSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true, maxlength: 24 },
    conversationKeys: { type: [String], default: [] },
    createdAt: { type: Date, default: Date.now },
  },
  { _id: true }
);
// Per-user "clear chat" watermark. When a user clears a conversation, we record
// the moment here rather than deleting any shared message documents — clearing
// is a *local* action that only hides messages from this user's own view, on all
// their devices. Messages with createdAt <= clearedAt are hidden for this user in
// that conversation; anything newer shows normally. This preserves E2E ciphertext,
// never affects the peer or other group members, and never deletes the group.
const clearedChatSchema = new mongoose.Schema(
  {
    conversationKey: { type: String, required: true },
    clearedAt: { type: Date, default: Date.now },
    // Which slice of the conversation this entry hides. 'all' matches the
    // original single-watermark behavior. Multiple scoped entries can
    // coexist for the same conversationKey (e.g. photos cleared yesterday,
    // videos cleared today) — each is applied independently on read.
    scope: {
      type: String,
      enum: ['all', 'photo', 'video', 'voice', 'document', 'text'],
      default: 'all',
    },
  },
  { _id: false }
);
const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      minlength: 3,
      maxlength: 30,
    },
    displayName: {
      type: String,
      trim: true,
      maxlength: 60,
      default: '',
    },
    bio: {
      type: String,
      trim: true,
      maxlength: 300,
      default: '',
    },
    /**
     * Short, user-authored status line (e.g. "Busy studying", "In a meeting").
     * Purely cosmetic and entirely separate from the technical online/offline
     * presence state — the two coexist. Optional; empty string means "no status".
     */
    statusText: {
      type: String,
      trim: true,
      maxlength: 100,
      default: '',
    },
    phone: {
      type: String,
      trim: true,
      maxlength: 32,
      default: '',
    },
     dateOfBirth: {
      type: Date,
      default: null,
    },
    /** IANA timezone name, auto-captured client-side (e.g. 'Asia/Karachi'). Used to schedule birthday notifications in the user's local time. */
    timezone: {
      type: String,
      trim: true,
      maxlength: 64,
      default: 'UTC',
    },
    /** Internal — prevents the birthday job from notifying friends twice in the same year. Never exposed via JSON. */
    lastBirthdayNotifiedYear: {
      type: Number,
      default: null,
      select: false,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      lowercase: true,
    },
    emailVerified: {
      type: Boolean,
      default: false,
    },
    emailVerifyToken: { type: String, select: false },
    emailVerifyExpires: { type: Date, select: false },
    password: {
      type: String,
      required() {
        return !this.isSystemUser;
      },
      select: false,
    },
    isSystemUser: {
      type: Boolean,
      default: false,
      immutable: true,
      index: true,
    },
    systemRole: {
      type: String,
      enum: ['quantum_ai', 'quantum_logics'],
      immutable: true,
    },
    verified: {
      type: Boolean,
      default: false,
      immutable: true,
    },
    passwordResetToken: { type: String, select: false },
    passwordResetExpires: { type: Date, select: false },
    totpSecret: { type: String, select: false },
    totpEnabled: { type: Boolean, default: false },
    vaultPasswordHash: { type: String, select: false, default: null },
    vaultEnabled: { type: Boolean, default: false },
    vaultedPeers: [
      {
        peer: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
        addedAt: { type: Date, default: Date.now },
      },
    ],
    // Chat Lock: one PIN per user, plus the set of conversations it protects.
    chatLockPinHash: { type: String, select: false, default: null },
    chatLockEnabled: { type: Boolean, default: false },
    chatLockFailedAttempts: { type: Number, default: 0, select: false },
    chatLockLockedUntil: { type: Date, default: null, select: false },
    lockedChats: [
      {
        _id: false,
        conversationKey: { type: String, required: true },
        addedAt: { type: Date, default: Date.now },
      },
    ],
    publicKeys: {
      type: [String],
      required: true,
      validate: {
        validator: (arr) => Array.isArray(arr) && arr.length === KEY_SET_SIZE && arr.every((k) => HEX_64.test(k)),
        message: `publicKeys must contain exactly ${KEY_SET_SIZE} 64-character hex public keys`,
      },
    },
    keyRotatedAt: {
      type: Date,
      default: Date.now,
    },
    lastLoginAt: {
      type: Date,
    },
    /** Last REST/socket presence heartbeat — used when Socket.IO is unavailable (e.g. Vercel). */
    presenceAt: {
      type: Date,
      default: null,
      index: true,
    },
    typingTo: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      default: null,
    },
    typingGroupId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Group',
      default: null,
    },
    typingAt: {
      type: Date,
      default: null,
    },
    privacy: {
      type: privacySchema,
      default: () => ({}),
    },
    notificationSettings: {
      type: notificationSettingsSchema,
      default: () => ({}),
    },
    mutedChats: {
      type: [mutedChatSchema],
      default: [],
    },
    chatFolders: {
      type: [chatFolderSchema],
      default: [],
    },
    clearedConversations: {
      type: [clearedChatSchema],
      default: [],
    },
    importantMessages: {
      type: [{
        messageId: { type: mongoose.Schema.Types.ObjectId, ref: 'Message', required: true },
        markedAt: { type: Date, default: Date.now },
      }],
      default: [],
    },
    blockedUsers: [
  {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
  },
],
friends: [
  {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
  },
],
    /**
     * Cached moderation state, recomputed on every new (non-duplicate,
     * trusted) report against this account — see reportController.js.
     * Never derive this by re-querying the Report collection on every
     * read; it's denormalized here specifically so reads stay cheap.
     */
    moderation: {
      reportCount: { type: Number, default: 0 },
      // Per-reason tally, e.g. { spam: 5, harassment: 2 } — lets the
      // "most common reason" be read directly with no aggregation query.
      reasonCounts: { type: Map, of: Number, default: () => new Map() },
      status: {
        type: String,
        enum: ['none', 'flagged', 'restricted'],
        default: 'none',
      },
      lastReportedAt: { type: Date, default: null },
    },
    
    preferredLanguage: {
      type: String,
      trim: true,
      minlength: 2,
      maxlength: 10,
      default: 'en',
    },
    transliteratedNames: {
      type: new mongoose.Schema(
        {
          ur: { type: String, trim: true, default: '' },
          ar: { type: String, trim: true, default: '' },
          fa: { type: String, trim: true, default: '' },
          hi: { type: String, trim: true, default: '' },
          zh: { type: String, trim: true, default: '' },
          ru: { type: String, trim: true, default: '' },
        },
        { _id: false }
      ),
      default: () => ({}),
    },
    avatarPath: {
      type: String,
      default: null,
    },
    avatarStorageProvider: {
      type: String,
      enum: ['local', 'cloudinary'],
      default: null,
    },
    avatarMimeType: {
      type: String,
      default: null,
    },
    // Personal invite link, auto-generated on first save. Used for
    // "invite a friend" referral tracking — never exposed on other users'
    // public profiles, only to the account holder (toSelfJSON) and via the
    // dedicated public preview endpoint by code.
    referralCode: {
      type: String,
      unique: true,
      sparse: true,
      index: true,
    },
    // Set once at signup if a valid referralCode was used. Null for anyone
    // who joined without one, or whose referrer's code was invalid/expired.
    referredBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      default: null,
    },
  },
  { timestamps: true }
);

// Older builds stored statusNotifications: 'favorites_only', later renamed to
// 'selected'. Mongoose validates the whole document on save, so an account
// still carrying the old value failed *every* save (chat folders, mute, ...).
// Upgrade it in place before validation runs.
userSchema.pre('validate', function upgradeLegacyNotificationSettings(next) {
  const ns = this.notificationSettings;
  if (ns && ns.statusNotifications === 'favorites_only') {
    ns.statusNotifications = 'selected';
  }
  next();
});

userSchema.pre('save', function generateReferralCode(next) {
  if (!this.referralCode) {
    this.referralCode = crypto.randomBytes(4).toString('hex');
  }
  next();
});
userSchema.pre('save', async function hashPassword(next) {
  if (!this.isModified('password')) return next();
  if (!this.password) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

userSchema.methods.comparePassword = function comparePassword(candidate) {
  return bcrypt.compare(candidate, this.password);
};

userSchema.methods.compareVaultPassword = function compareVaultPassword(candidate) {
  if (!this.vaultPasswordHash) return Promise.resolve(false);
  return bcrypt.compare(candidate, this.vaultPasswordHash);
};
userSchema.methods.createVaultUnlockToken = function createVaultUnlockToken() {
  return jwt.sign(
    { sub: String(this._id), scope: 'vault' },
    process.env.JWT_SECRET,
    { algorithm: 'HS256', expiresIn: '15m' }
  );
};
userSchema.methods.compareChatLockPin = function compareChatLockPin(candidate) {
      if (!this.chatLockPinHash) return Promise.resolve(false);
      return bcrypt.compare(String(candidate || ''), this.chatLockPinHash);
    };
    userSchema.methods.createChatLockToken = function createChatLockToken() {
      return jwt.sign(
        { sub: String(this._id), scope: 'chatlock' },
        process.env.JWT_SECRET,
        { algorithm: 'HS256', expiresIn: '10m' }
      );
    };
userSchema.methods.createEmailVerifyToken = function createEmailVerifyToken() {
  const token = crypto.randomBytes(32).toString('hex');
  this.emailVerifyToken = crypto.createHash('sha256').update(token).digest('hex');
  this.emailVerifyExpires = new Date(Date.now() + 24 * 60 * 60 * 1000);
  return token;
};

userSchema.methods.createPasswordResetToken = function createPasswordResetToken() {
  const token = crypto.randomBytes(32).toString('hex');
  this.passwordResetToken = crypto.createHash('sha256').update(token).digest('hex');
  this.passwordResetExpires = new Date(Date.now() + 60 * 60 * 1000);
  return token;
};

/**
 * Minimal safety-warning payload for someone considering accepting a
 * friend request from this account — deliberately exposes only a boolean
 * and the single most common report reason, never the exact count and
 * never anything about who reported. Returns null below the 7-report
 * threshold, so callers can just check truthiness.
 */
userSchema.methods.getModerationSafetyWarning = function getModerationSafetyWarning() {
  const count = this.moderation?.reportCount || 0;
  if (count < 7) return null;
  const reasonCounts = this.moderation?.reasonCounts;
  let topReason = null;
  let topCount = 0;
  if (reasonCounts) {
    for (const [reason, n] of reasonCounts.entries()) {
      if (n > topCount) {
        topCount = n;
        topReason = reason;
      }
    }
  }
  return { reportedByMultiple: true, commonReason: topReason };
};

userSchema.methods.toPublicJSON = function toPublicJSON(viewerId) {
  let publicKeys = Array.isArray(this.publicKeys) ? this.publicKeys.filter(Boolean) : [];
  if (publicKeys.length === 0 && this.publicKey) {
    publicKeys = [this.publicKey];
  }

  const privacy = this.privacy || {};
  const lastSeenSetting = privacy.lastSeen || 'everyone';
  let showLastSeen = false;
  if (viewerId && String(viewerId) === String(this._id)) {
    showLastSeen = true;
  } else if (lastSeenSetting === 'everyone') {
    showLastSeen = true;
  } else if (lastSeenSetting === 'friends' && viewerId) {
    const friendIds = (this.friends || []).map((f) => String(f._id || f));
    showLastSeen = friendIds.includes(String(viewerId));
  }

  const profileVisibilitySetting = privacy.profileVisibility || 'everyone';
  let showProfileDetails = false;
  if (profileVisibilitySetting === 'everyone') {
    showProfileDetails = true;
  } else if (profileVisibilitySetting === 'friends' && viewerId) {
    if (String(viewerId) === String(this._id)) {
      showProfileDetails = true;
    } else {
      const friendIds = (this.friends || []).map((f) => String(f._id || f));
      showProfileDetails = friendIds.includes(String(viewerId));
    }
  } else if (profileVisibilitySetting === 'onlyMe' && viewerId) {
    showProfileDetails = String(viewerId) === String(this._id);
  }

  const birthdayVisibilitySetting = privacy.birthdayVisibility || 'everyone';
  let showBirthday = false;
  if (birthdayVisibilitySetting === 'everyone') {
    showBirthday = true;
  } else if (birthdayVisibilitySetting === 'friends' && viewerId) {
    if (String(viewerId) === String(this._id)) {
      showBirthday = true;
    } else {
      const friendIds = (this.friends || []).map((f) => String(f._id || f));
      showBirthday = friendIds.includes(String(viewerId));
    }
  } else if (birthdayVisibilitySetting === 'onlyMe' && viewerId) {
    showBirthday = String(viewerId) === String(this._id);
  }

  let readReceipts = privacy.readReceipts;
  if (typeof readReceipts === 'boolean') {
    readReceipts = readReceipts ? 'everyone' : 'nobody';
  } else if (!['everyone', 'friends', 'nobody'].includes(readReceipts)) {
    readReceipts = 'everyone';
  }

  const onlineStatus =
    privacy.onlineStatus ||
    (privacy.online === 'nobody' ? 'selected' : privacy.online) ||
    'everyone';

  return {
    id: this._id,
    username: this.username,
    displayName: this.displayName || '',
    statusText: showProfileDetails ? (this.statusText || '') : '',
    bio: showProfileDetails ? (this.bio || '') : '',
    phone: showProfileDetails ? (this.phone || '') : '',
    birthday: (showBirthday && this.dateOfBirth) ? this.dateOfBirth : null,
    publicKeys: publicKeys.map((k) => String(k).toLowerCase()),
    keyRotatedAt: this.keyRotatedAt,
    lastLoginAt: showLastSeen ? this.lastLoginAt : null,
    hasAvatar: showProfileDetails ? Boolean(this.avatarPath) : false,
      profileLocked: !showProfileDetails,   // ← new
  birthdayLocked: !showBirthday, 
    privacy: {
      lastSeen: privacy.lastSeen || 'everyone',
      online: privacy.online || 'everyone',
      onlineStatus,
      onlineStatusVisibleTo: Array.isArray(privacy.onlineStatusVisibleTo)
        ? privacy.onlineStatusVisibleTo.map((id) => String(id._id || id))
        : [],
      readReceipts,
      typingIndicator: privacy.typingIndicator !== false,
      whoCanMessage: privacy.whoCanMessage || 'everyone',
      discoverable: privacy.discoverable || 'everyone',
      story: privacy.story || 'everyone',
      storyViewers: Array.isArray(privacy.storyViewers)
        ? privacy.storyViewers.map((id) => String(id._id || id))
        : [],
      profileVisibility: privacy.profileVisibility || 'everyone',
      birthdayVisibility: privacy.birthdayVisibility || 'everyone',
      whoCanMention: privacy.whoCanMention || 'everyone',
      whoCanAddToGroups: privacy.whoCanAddToGroups || 'everyone',
      whoCanInviteViaGroupLink: privacy.whoCanInviteViaGroupLink || 'everyone',
      whoCanCreateGroupsWithMe: privacy.whoCanCreateGroupsWithMe || 'everyone',
      groupMentions: privacy.groupMentions || 'everyone',
      screenshotProtection: privacy.screenshotProtection === true,
      viewStoriesAnonymously: privacy.viewStoriesAnonymously === true,
    },
    isSystemUser: Boolean(this.isSystemUser),
    systemRole: this.systemRole || null,
    verified: Boolean(this.verified),
    preferredLanguage: this.preferredLanguage || 'en',
    transliteratedNames: this.transliteratedNames
      ? (typeof this.transliteratedNames.toObject === 'function'
          ? this.transliteratedNames.toObject()
          : this.transliteratedNames)
      : {},
  };
};

userSchema.methods.toSelfJSON = function toSelfJSON() {
  return {
    ...this.toPublicJSON(this._id),
    email: this.email,
    phone: this.phone || '',
    preferredLanguage: this.preferredLanguage || 'en',
    dateOfBirth: this.dateOfBirth,
    timezone: this.timezone || 'UTC',
    // Own moderation status only — this is never in toPublicJSON, so no
    // one else can see it. count/status shown to the account holder
    // directly (unlike getModerationSafetyWarning(), which is the
    // minimal-disclosure version shown to OTHERS in a friend-request context).
    moderation: {
      status: this.moderation?.status || 'none',
      reportCount: this.moderation?.reportCount || 0,
    },
    emailVerified: Boolean(this.emailVerified),
    lastLoginAt: this.lastLoginAt,
    blockedUsers: Array.isArray(this.blockedUsers) ? this.blockedUsers.map((id) => String(id)) : [],
    friends: Array.isArray(this.friends) ? this.friends.map((id) => String(id)) : [],
    notificationSettings: normalizeNotificationSettings(this.notificationSettings),
    mutedChats: Array.isArray(this.mutedChats) ? this.mutedChats.map((m) => ({
      conversationKey: m.conversationKey,
      expiresAt: m.expiresAt,
    })) : [],
    chatFolders: Array.isArray(this.chatFolders) ? this.chatFolders.map((f) => ({
      id: String(f._id),
      name: f.name,
      conversationKeys: (f.conversationKeys || []).map(String),
    })) : [],
    clearedConversations: Array.isArray(this.clearedConversations) ? this.clearedConversations.map((c) => ({
      conversationKey: c.conversationKey,
      clearedAt: c.clearedAt,
      scope: c.scope || 'all',
    })) : [],
    importantMessages: Array.isArray(this.importantMessages) ? this.importantMessages.map((entry) => ({
      messageId: String(entry.messageId),
      markedAt: entry.markedAt,
    })) : [],
    totpEnabled: Boolean(this.totpEnabled),
    chatLockEnabled: Boolean(this.chatLockEnabled),
    lockedChats: Array.isArray(this.lockedChats) ? this.lockedChats.map((l) => l.conversationKey) : [],
    referralCode: this.referralCode || null,
  };
};

export default mongoose.model('User', userSchema, 'users');
