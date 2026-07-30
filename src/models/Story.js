import mongoose from 'mongoose';

const STORY_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_DURATION_MS = 60 * 1000;
const MIN_TTL_MS = 15 * 60 * 1000;        // 15 minutes minimum
const MAX_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days maximum
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
    mediaType: { type: String, enum: ['image', 'video', 'audio'], required: true },
    filename: { type: String, required: true },
    mimetype: { type: String, required: true },
    size: { type: Number, required: true },
    storagePath: { type: String, required: true },
    storageProvider: {
      type: String,
      enum: ['local', 'google-drive', 'memory'],
      default: 'google-drive',
    },
    durationMs: { type: Number, default: 0, max: MAX_DURATION_MS },
    caption: { type: String, maxlength: 200, default: '' },
    expiresAt: { type: Date, required: true, index: true },
    sealed: { type: Boolean, default: false },
    /** AES-GCM IV for sealed media (base64); content key is in per-viewer envelopes. */
    contentIv: { type: String, default: undefined },
    envelopes: { type: [storyEnvelopeSchema], default: undefined },
    envelopeNonce: { type: String, default: undefined },
    envelopeEphemeralPublicKey: { type: String, default: undefined },
    envelopeTargetHint: { type: String, default: undefined },
  },
  { timestamps: true }
);

storySchema.statics.ttlMs = STORY_TTL_MS;
storySchema.statics.maxDurationMs = MAX_DURATION_MS;
storySchema.statics.minTtlMs = MIN_TTL_MS;
storySchema.statics.maxTtlMs = MAX_TTL_MS;

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
    createdAt: this.createdAt,
    expiresAt: this.expiresAt,
    sealed: Boolean(this.sealed),
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

export default mongoose.model('Story', storySchema, 'stories');
