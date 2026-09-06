import mongoose from 'mongoose';

const STORY_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_DURATION_MS = 60 * 1000;
const MIN_TTL_MS = 15 * 60 * 1000; // 15 minutes minimum
const MAX_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days maximum
const DRAFT_RETENTION_MS = 30 * 24 * 60 * 60 * 1000; // keep drafts 30 days
const HEX_64 = /^[0-9a-f]{64}$/i;

const storyEnvelopeSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    ciphertext: { type: String, required: true },
    nonce: { type: String, required: true },
    ephemeralPublicKey: { type: String, required: true, match: HEX_64 },
    targetPublicKey: { type: String, required: true, match: HEX_64 },
  },
  { _id: false }
);

const storySchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    mediaType: { type: String, enum: ['image', 'video', 'audio', 'text'], required: true },
    filename: { type: String, required: true },
    mimetype: { type: String, required: true },
    size: { type: Number, required: true },
    storagePath: { type: String, default: '' },
    storageProvider: {
      type: String,
      enum: ['local', 'cloudinary', 'memory', 'none'],
      default: 'cloudinary',
    },
    durationMs: { type: Number, default: 0, max: MAX_DURATION_MS },
    caption: { type: String, maxlength: 200, default: '' },
    /** Plaintext status body (unsealed text stories only). */
    textContent: { type: String, maxlength: 700, default: '' },
    /** Visual style for text stories. */
    textStyle: {
      background: { type: String, maxlength: 40, default: '' },
      font: { type: String, maxlength: 40, default: '' },
      align: { type: String, enum: ['', 'left', 'center', 'right'], default: '' },
    },
    /** Intended live visibility window (applied when published). */
    ttlMs: { type: Number, default: STORY_TTL_MS, min: MIN_TTL_MS, max: MAX_TTL_MS },
    /**
     * draft — owner-only, not live
     * scheduled — owner-only until publishAt
     * published — visible to audience until expiresAt
     */
    status: {
      type: String,
      enum: ['draft', 'scheduled', 'published'],
      default: 'published',
      index: true,
    },
    /** When status=scheduled, go live at this time. */
    publishAt: { type: Date, default: null, index: true },
    expiresAt: { type: Date, required: true, index: true },
    sealed: { type: Boolean, default: false },
    allowReplies: { type: Boolean, default: true },
    /** AES-GCM IV for sealed media (base64); content key is in per-viewer envelopes. */
    contentIv: { type: String, default: undefined },
    envelopes: { type: [storyEnvelopeSchema], default: undefined },
    envelopeNonce: { type: String, default: undefined },
    envelopeEphemeralPublicKey: { type: String, default: undefined },
    envelopeTargetHint: { type: String, default: undefined },
    views: {
      type: [
        {
          user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
          viewedAt: { type: Date, default: Date.now },
        },
      ],
      default: [],
    },
  },
  { timestamps: true }
);

storySchema.index({ status: 1, publishAt: 1 });
storySchema.index({ user: 1, status: 1, updatedAt: -1 });

storySchema.statics.ttlMs = STORY_TTL_MS;
storySchema.statics.maxDurationMs = MAX_DURATION_MS;
storySchema.statics.minTtlMs = MIN_TTL_MS;
storySchema.statics.maxTtlMs = MAX_TTL_MS;
storySchema.statics.draftRetentionMs = DRAFT_RETENTION_MS;

storySchema.methods.toPublicJSON = function toPublicJSON() {
  return {
    id: this._id,
    user: this.user?._id || this.user,
    mediaType: this.mediaType,
    filename: this.filename,
    mimetype: this.mimetype,
    size: this.size,
    durationMs: this.durationMs || 0,
    caption: this.caption || '',
    textContent: this.mediaType === 'text' && !this.sealed ? this.textContent || '' : '',
    textStyle:
      this.mediaType === 'text'
        ? {
            background: this.textStyle?.background || '',
            font: this.textStyle?.font || '',
            align: this.textStyle?.align || 'center',
          }
        : undefined,
    ttlMs: this.ttlMs || STORY_TTL_MS,
    status: this.status || 'published',
    publishAt: this.publishAt || null,
    createdAt: this.createdAt,
    updatedAt: this.updatedAt,
    expiresAt: this.expiresAt,
    sealed: Boolean(this.sealed),
    allowReplies: this.allowReplies !== false,
    contentIv: this.contentIv || undefined,
    envelopes: Array.isArray(this.envelopes)
      ? this.envelopes.map((e) => ({
          user: e.user,
          ciphertext: e.ciphertext,
          nonce: e.nonce,
          ephemeralPublicKey: e.ephemeralPublicKey,
          targetPublicKey: e.targetPublicKey,
        }))
      : undefined,
    envelopeNonce: this.envelopeNonce || undefined,
    envelopeEphemeralPublicKey: this.envelopeEphemeralPublicKey || undefined,
    envelopeTargetHint: this.envelopeTargetHint || undefined,
  };
};

storySchema.methods.viewerCount = function viewerCount() {
  return Array.isArray(this.views) ? this.views.length : 0;
};

export default mongoose.model('Story', storySchema, 'stories');
