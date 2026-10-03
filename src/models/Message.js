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
const deliveryReceiptSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    at: { type: Date, required: true },
  },
  { _id: false }
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
const transcriptEntrySchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    status: {
      type: String,
      enum: ['queued', 'running', 'completed', 'failed', 'unsupported'],
      default: 'queued',
    },
    model: { type: String, default: 'Xenova/whisper-tiny' },
    revision: { type: String, default: '5332fcc35e32a33b86612b9a57a89be7906102b1' },
    language: { type: String, default: undefined },
    claimToken: { type: String, default: undefined },
    claimLeaseUntil: { type: Date, default: null },
    encryptedText: { type: String, default: undefined },
    nonce: { type: String, default: undefined },
    ephemeralPublicKey: { type: String, default: undefined, match: HEX_64 },
    targetPublicKey: { type: String, default: undefined, match: HEX_64 },
    error: { type: String, default: undefined },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now },
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
const editHistoryEntrySchema = new mongoose.Schema(
  {
    forRecipient: { type: envelopeSchema },
    forSender: { type: envelopeSchema },
    content: { type: String, maxlength: 8000 },
    envelopes: { type: [memberEnvelopeSchema], default: undefined },
    editedAt: { type: Date, required: true },
  },
  { _id: false }
);
const messageSchema = new mongoose.Schema(
  {
    from: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    // Client-generated id used to make safe offline retries idempotent.
    clientMessageId: { type: String, maxlength: 100, trim: true },
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
    editHistory: { type: [editHistoryEntrySchema], default: undefined },
    deliveredAt: { type: Date },
    readAt: { type: Date },
        // Group-only per-member delivery/read receipts. DMs keep using the
    // single deliveredAt/readAt fields above — untouched.
    deliveredTo: { type: [deliveryReceiptSchema], default: undefined },
    readBy: { type: [deliveryReceiptSchema], default: undefined },
    kind: {
      type: String,
      enum: ['text', 'announcement', 'poll', 'event', 'file', 'ai', 'ai_note', 'system', 'story_mention'],
      default: 'text',
    },
    // Set only when kind === 'story_mention' — lets the client render a
    // "View Story" link/preview. Just an id reference, never sensitive.
    storyRef: { type: mongoose.Schema.Types.ObjectId, ref: 'Story', default: undefined },
    // Attachment category snapshot at send time — lets "Clear chat" filter by
    // photo/video/voice/document without joining Attachment on every read.
    // Absent (undefined) for messages with no attachment (plain text).
    mediaCategory: {
      type: String,
      enum: ['photo', 'video', 'voice', 'document'],
      default: undefined,
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
    expiresAt: { type: Date, default: null },
    // Time Capsule: sealed exactly like any other DM at send time — the
    // encryption doesn't change. The server just withholds forRecipient/
    // forSender from API responses (see toClientMessage) until unlocksAt
    // has passed. DMs only for now.
    timeCapsule: { type: Boolean, default: false },
    unlocksAt: { type: Date, default: null },
    capsuleDeliveredAt: { type: Date, default: null },
    // WhatsApp-style view-once media: photo / video / voice can be opened once,
    // then the ciphertext is purged and a tombstone remains.
    viewOnce: { type: Boolean, default: false },
    viewOnceMediaKind: {
      type: String,
      enum: ['image', 'video', 'audio'],
      default: undefined,
    },
    viewOnceOpenedAt: { type: Date, default: null },
    viewOnceOpenedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    // Each direct-message participant runs ASR locally and seals their own
    // transcript envelope before it reaches the backend.
    transcription: {
      status: {
        type: String,
        enum: ['queued', 'running', 'completed', 'failed', 'unsupported'],
        default: 'completed',
      },
      model: { type: String, default: 'Xenova/whisper-tiny' },
      revision: { type: String, default: '5332fcc35e32a33b86612b9a57a89be7906102b1' },
      language: { type: String, default: undefined },
      claimToken: { type: String, default: undefined },
      claimLeaseUntil: { type: Date, default: null },
      claimedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
      encryptedText: { type: String, default: undefined },
      nonce: { type: String, default: undefined },
      ephemeralPublicKey: { type: String, default: undefined, match: HEX_64 },
      targetPublicKey: { type: String, default: undefined, match: HEX_64 },
      error: { type: String, default: undefined },
      entries: { type: [transcriptEntrySchema], default: [] },
      createdAt: { type: Date, default: Date.now },
      updatedAt: { type: Date, default: Date.now },
    },
    // Vault decoy separation: when set, this message only belongs to the
    // decoy thread for this user's locked vault view of the conversation.
    // Never set for group messages. Plain metadata — does not touch the
    // sealed envelopes/encryption at all.
    decoyFor: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null, index: true },
  },
  { timestamps: true }
);
messageSchema.index({ from: 1, to: 1, createdAt: 1 });
messageSchema.index({ group: 1, createdAt: 1 });
messageSchema.index({ decoyFor: 1, from: 1, to: 1, createdAt: 1 });
messageSchema.index(
  { from: 1, clientMessageId: 1 },
  { unique: true, partialFilterExpression: { clientMessageId: { $type: 'string' } } }
);
messageSchema.index({ 'aiMetadata.requestId': 1 }, { unique: true, sparse: true });
messageSchema.index({ expiresAt: 1 }, { sparse: true });
messageSchema.index({ timeCapsule: 1, unlocksAt: 1, capsuleDeliveredAt: 1 }, { sparse: true });

messageSchema.pre('validate', function ensureCapsuleShape(next) {
  if (!this.timeCapsule) return next();
  if (this.group) {
    return next(new Error('Time capsule messages are only supported for direct messages right now'));
  }
  const unlocksAt = this.unlocksAt ? new Date(this.unlocksAt) : null;
  if (!unlocksAt || Number.isNaN(unlocksAt.getTime())) {
    return next(new Error('Time capsule messages require a valid unlocksAt date'));
  }
  if (unlocksAt.getTime() <= Date.now()) {
    return next(new Error('unlocksAt must be in the future'));
  }
  next();
});

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
