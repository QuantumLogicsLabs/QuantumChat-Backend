import mongoose from 'mongoose';

const HEX_64 = /^[0-9a-f]{64}$/i;
const CALL_SIGNAL_TTL_MS = 2 * 60 * 1000;

const envelopeSchema = new mongoose.Schema(
  {
    ciphertext: { type: String, required: true, maxlength: 32_768 },
    nonce: { type: String, required: true, maxlength: 256 },
    ephemeralPublicKey: { type: String, required: true, match: HEX_64 },
    targetPublicKey: { type: String, required: true, match: HEX_64 },
  },
  { _id: false }
);

const callSignalSchema = new mongoose.Schema(
  {
    from: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    to: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    callId: { type: String, required: true, maxlength: 128, index: true },
    event: {
      type: String,
      required: true,
      enum: [
        'call:invite',
        'call:accept',
        'call:reject',
        'call:hangup',
        'call:offer',
        'call:answer',
        'call:ice',
      ],
    },
    envelope: { type: envelopeSchema, required: true },
    expiresAt: {
      type: Date,
      required: true,
      default: () => new Date(Date.now() + CALL_SIGNAL_TTL_MS),
      expires: 0,
    },
  },
  { timestamps: { createdAt: true, updatedAt: false } }
);

callSignalSchema.index({ to: 1, createdAt: 1 });

export default mongoose.model('CallSignal', callSignalSchema);
