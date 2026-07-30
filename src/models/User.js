import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';

const HEX_64 = /^[0-9a-f]{64}$/i;
export const KEY_SET_SIZE = 5;

const privacySchema = new mongoose.Schema(
  {
    lastSeen: { type: String, enum: ['everyone', 'nobody'], default: 'everyone' },
    online: { type: String, enum: ['everyone', 'nobody'], default: 'everyone' },
    readReceipts: { type: Boolean, default: true },
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
    phone: {
      type: String,
      trim: true,
      maxlength: 32,
      default: '',
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
      enum: ['quantum_ai'],
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
    privacy: {
      type: privacySchema,
      default: () => ({}),
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
    
    avatarPath: {
      type: String,
      default: null,
    },
    avatarStorageProvider: {
      type: String,
      enum: ['local', 'google-drive'],
      default: null,
    },
    avatarMimeType: {
      type: String,
      default: null,
    },
  },
  { timestamps: true }
);

userSchema.pre('save', async function hashPassword(next) {
  if (!this.isModified('password')) return next();
  if (!this.password) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

userSchema.methods.comparePassword = function comparePassword(candidate) {
  return bcrypt.compare(candidate, this.password);
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

userSchema.methods.toPublicJSON = function toPublicJSON() {
  let publicKeys = Array.isArray(this.publicKeys) ? this.publicKeys.filter(Boolean) : [];
  if (publicKeys.length === 0 && this.publicKey) {
    publicKeys = [this.publicKey];
  }

  const privacy = this.privacy || {};
  const showLastSeen = privacy.lastSeen !== 'nobody';

  return {
    id: this._id,
    username: this.username,
    displayName: this.displayName || '',
    bio: this.bio || '',
    publicKeys: publicKeys.map((k) => String(k).toLowerCase()),
    keyRotatedAt: this.keyRotatedAt,
    lastLoginAt: showLastSeen ? this.lastLoginAt : null,
    hasAvatar: Boolean(this.avatarPath),
    privacy: {
      lastSeen: privacy.lastSeen || 'everyone',
      online: privacy.online || 'everyone',
      readReceipts: privacy.readReceipts !== false,
    },
    isSystemUser: Boolean(this.isSystemUser),
    systemRole: this.systemRole || null,
    verified: Boolean(this.verified),
  };
};

userSchema.methods.toSelfJSON = function toSelfJSON() {
  return {
    ...this.toPublicJSON(),
    email: this.email,
    phone: this.phone || '',
    emailVerified: Boolean(this.emailVerified),
    lastLoginAt: this.lastLoginAt,
    blockedUsers: Array.isArray(this.blockedUsers) ? this.blockedUsers.map((id) => String(id)) : [],
    friends: Array.isArray(this.friends) ? this.friends.map((id) => String(id)) : [],   // ← add this line
    totpEnabled: Boolean(this.totpEnabled),
  };
};

export default mongoose.model('User', userSchema, 'users');
