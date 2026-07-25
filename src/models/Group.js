import mongoose from 'mongoose';

const groupSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
      minlength: 2,
      maxlength: 60,
    },
    description: {
      type: String,
      trim: true,
      maxlength: 500,
      default: '',
    },
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
    },
    members: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
      },
    ],
    admins: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
      },
    ],
    photoPath: { type: String },
    photoMimeType: { type: String },
    inviteCode: {
      type: String,
      sparse: true,
      unique: true,
      index: true,
    },
    inviteEnabled: {
      type: Boolean,
      default: false,
    },
    pinnedMessageIds: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Message',
      },
    ],
    onlyAdminsCanPost: {
      type: Boolean,
      default: false,
    },
    onlyAdminsCanAddMembers: {
      type: Boolean,
      default: true,
    },
    /** private = encrypted invite-only; public = plaintext, discoverable */
    visibility: {
      type: String,
      enum: ['private', 'public'],
      default: 'private',
      index: true,
    },
    /**
     * private groups use invite; public groups use open or request.
     * invite is forced for private groups.
     */
    joinPolicy: {
      type: String,
      enum: ['invite', 'open', 'request'],
      default: 'invite',
    },
    quantumAI: {
      enabled: { type: Boolean, default: false },
      invocationPolicy: { type: String, enum: ['members', 'admins'], default: 'members' },
      maxContextMessages: { type: Number, min: 0, max: 20, default: 5 },
      dailyLimit: { type: Number, min: 1, max: 1000, default: 50 },
      usageDay: { type: String, default: '' },
      usageCount: { type: Number, default: 0 },
    },
  },
  { timestamps: true }
);

groupSchema.index({ members: 1 });
groupSchema.index({ visibility: 1, updatedAt: -1 });

groupSchema.methods.isMember = function isMember(userId) {
  return (this.members || []).some((m) => String(m._id || m) === String(userId));
};

groupSchema.methods.isAdmin = function isAdmin(userId) {
  const id = String(userId);
  const admins = this.admins || [];
  if (admins.length) return admins.some((a) => String(a._id || a) === id);
  return String(this.createdBy?._id || this.createdBy) === id;
};

groupSchema.methods.toPublicJSON = function toPublicJSON() {
  const createdBy = this.createdBy?._id || this.createdBy;
  let admins = (this.admins || []).map((a) => String(a._id || a));
  if (!admins.length && createdBy) admins = [String(createdBy)];

  return {
    id: this._id,
    name: this.name,
    description: this.description || '',
    createdBy,
    members: (this.members || []).map((m) => {
      if (m && typeof m === 'object' && m.toPublicJSON) return m.toPublicJSON();
      if (m && typeof m === 'object' && m._id) {
        return {
          id: m._id,
          username: m.username,
          email: m.email,
          publicKeys: m.publicKeys || [],
          lastLoginAt: m.lastLoginAt,
          hasAvatar: Boolean(m.avatarPath),
          isSystemUser: Boolean(m.isSystemUser),
          systemRole: m.systemRole || null,
          verified: Boolean(m.verified),
        };
      }
      return { id: m };
    }),
    admins,
    hasPhoto: Boolean(this.photoPath),
    inviteEnabled: Boolean(this.inviteEnabled && this.inviteCode),
    inviteCode: this.inviteEnabled ? this.inviteCode || null : null,
    pinnedMessageIds: (this.pinnedMessageIds || []).map((id) => String(id)),
    onlyAdminsCanPost: Boolean(this.onlyAdminsCanPost),
    onlyAdminsCanAddMembers: Boolean(this.onlyAdminsCanAddMembers),
    visibility: this.visibility === 'public' ? 'public' : 'private',
    joinPolicy:
      this.visibility === 'public'
        ? this.joinPolicy === 'request'
          ? 'request'
          : 'open'
        : 'invite',
    memberCount: (this.members || []).length,
    quantumAI: {
      enabled: Boolean(this.quantumAI?.enabled),
      invocationPolicy: this.quantumAI?.invocationPolicy || 'members',
      maxContextMessages: this.quantumAI?.maxContextMessages ?? 5,
      dailyLimit: this.quantumAI?.dailyLimit ?? 50,
    },
    createdAt: this.createdAt,
    updatedAt: this.updatedAt,
  };
};

export default mongoose.model('Group', groupSchema, 'groups');
