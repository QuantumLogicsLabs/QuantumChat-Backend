import mongoose from 'mongoose';

const savedReplySchema = new mongoose.Schema(
  {
    owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    shortcut: { type: String, required: true, trim: true, maxlength: 40 },
    normalizedShortcut: { type: String, required: true, lowercase: true, trim: true },
    message: { type: String, required: true, trim: true, maxlength: 10000 },
  },
  { timestamps: true }
);

savedReplySchema.index({ owner: 1, normalizedShortcut: 1 }, { unique: true });
savedReplySchema.index({ owner: 1, createdAt: 1 });

savedReplySchema.methods.toPublicJSON = function toPublicJSON() {
  return {
    id: String(this._id),
    shortcut: this.shortcut,
    message: this.message,
    createdAt: this.createdAt,
    updatedAt: this.updatedAt,
  };
};

export default mongoose.model('SavedReply', savedReplySchema, 'saved_replies');
