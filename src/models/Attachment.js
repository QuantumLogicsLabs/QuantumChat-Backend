import mongoose from 'mongoose';

const HEX_64 = /^[0-9a-f]{64}$/i;

const attachmentSchema = new mongoose.Schema(
  {
    owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    recipient: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    group: { type: mongoose.Schema.Types.ObjectId, ref: 'Group', index: true },
    filename: { type: String, required: true },
    mimetype: { type: String, required: true },
    size: { type: Number, required: true },
    // Ciphertext blob key (local relative path or Google Drive file id).
    storagePath: { type: String, required: true },
    storageProvider: {
      type: String,
      enum: ['local', 'google-drive', 'memory'],
      default: 'google-drive',
    },
    // DM sealed-box fields (optional for group secretbox attachments)
    nonce: { type: String },
    ephemeralPublicKey: { type: String, match: HEX_64 },
    targetPublicKey: { type: String, match: HEX_64 },
    forSenderStoragePath: { type: String },
    forSenderNonce: { type: String },
    forSenderEphemeralPublicKey: { type: String, match: HEX_64 },
    forSenderTargetPublicKey: { type: String, match: HEX_64 },
    // group = secretbox ciphertext; key is only in sealed message envelopes
    encryption: {
      type: String,
      enum: ['sealed', 'secretbox'],
      default: 'sealed',
    },
    secretboxNonce: { type: String },
  },
  { timestamps: true }
);

attachmentSchema.pre('validate', function ensureShape(next) {
  if (this.group) {
    this.encryption = 'secretbox';
    this.recipient = undefined;
    return next();
  }
  if (!this.recipient) {
    return next(new Error('DM attachments require a recipient'));
  }
  if (!this.nonce || !this.ephemeralPublicKey || !this.targetPublicKey) {
    return next(new Error('DM attachments require sealed-box metadata'));
  }
  this.encryption = 'sealed';
  next();
});

export default mongoose.model('Attachment', attachmentSchema, 'attachments');
