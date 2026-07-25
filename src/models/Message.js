import mongoose from 'mongoose';

const HEX_64 = /^[0-9a-f]{64}$/i;

const envelopeSchema = new mongoose.Schema(
  {
    ciphertext: { type: String, required: true },
    nonce: { type: String, required: true },
    ephemeralPublicKey: { type: String, required: true, match: HEX_64 },
    targetPublicKey: { type: String, required: true, match: HEX_64 },
  },
  { _id: false }
);

const reactionSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    forRecipient: { type: envelopeSchema },
    forSender: { type: envelopeSchema },
    emoji: { type: String, maxlength: 16 },
  },
  { _id: false, timestamps: { createdAt: true, updatedAt: false } }
);

const memberEnvelopeSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    ciphertext: { type: String, required: true },
    nonce: { type: String, required: true },
    ephemeralPublicKey: { type: String, required: true, match: HEX_64 },
    targetPublicKey: { type: String, required: true, match: HEX_64 },
  },
  { _id: false }
);

const pollVoteSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    optionIndex: { type: Number, required: true, min: 0 },
  },
  { _id: false }
);

const messageSchema = new mongoose.Schema(
  {
    from: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    to: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
    forRecipient: { type: envelopeSchema },
    forSender: { type: envelopeSchema },
    group: { type: mongoose.Schema.Types.ObjectId, ref: 'Group', index: true },
    envelopes: { type: [memberEnvelopeSchema], default: undefined },
    /** Plaintext body for public (non-E2E) group messages */
    content: { type: String, maxlength: 8000 },
    attachment: { type: mongoose.Schema.Types.ObjectId, ref: 'Attachment' },
    reactions: { type: [reactionSchema], default: [] },
    replyTo: { type: mongoose.Schema.Types.ObjectId, ref: 'Message' },
    editedAt: { type: Date },
    deliveredAt: { type: Date },
    readAt: { type: Date },
    kind: {
      type: String,
      enum: ['text', 'announcement', 'poll', 'event', 'file', 'ai', 'ai_note'],
      default: 'text',
    },
    mentionedUserIds: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    aiMetadata: {
      contentHash: { type: String, match: /^[0-9a-f]{64}$/i },
      requestedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
      model: { type: String, maxlength: 120 },
      requestId: { type: String },
    },
    pollVotes: { type: [pollVoteSchema], default: undefined },
    // Optional display metadata when this message was forwarded (plaintext was re-sealed).
    forwardedFrom: {
      username: { type: String },
      messageId: { type: mongoose.Schema.Types.ObjectId },
    },
    // Capability token: whether recipients may forward this message further.
    forwardPolicy: {
      allowForward: { type: Boolean, default: true },
      forwardUntil: { type: Date, default: null },
    },
    expiresAt: { type: Date, default: null, index: true },
  },
  { timestamps: true }
);

messageSchema.index({ from: 1, to: 1, createdAt: 1 });
messageSchema.index({ group: 1, createdAt: 1 });
messageSchema.index({ 'aiMetadata.requestId': 1 }, { unique: true, sparse: true });
messageSchema.index({ expiresAt: 1 }, { sparse: true });

messageSchema.pre('validate', function ensureShape(next) {
  const isGroup = Boolean(this.group);
  if (isGroup) {
    const hasContent = typeof this.content === 'string' && this.content.trim().length > 0;
    const hasEnvelopes = Array.isArray(this.envelopes) && this.envelopes.length >= 2;
    if (hasContent && !hasEnvelopes) {
      // Public group plaintext path
      this.envelopes = undefined;
      this.content = this.content.trim().slice(0, 8000);
    } else if (hasEnvelopes) {
      // Private encrypted path
      this.content = undefined;
    } else {
      return next(
        new Error('Group messages require envelopes (private) or non-empty content (public)')
      );
    }
    this.to = undefined;
    this.forRecipient = undefined;
    this.forSender = undefined;
  } else {
    if (!this.to || !this.forRecipient || !this.forSender) {
      return next(new Error('DM messages require to, forRecipient and forSender'));
    }
    this.group = undefined;
    this.envelopes = undefined;
    this.content = undefined;
  }
  next();
});

export default mongoose.model('Message', messageSchema, 'messages');
