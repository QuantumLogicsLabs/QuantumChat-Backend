import mongoose from 'mongoose';

/**
 * "Remind me about this message" — deliberately minimal. Stores only WHO
 * asked, WHICH message (by id) and WHEN. No message text, no ciphertext,
 * no conversation details: the push job looks the message up at send time
 * only to work out which chat to open.
 */
const reminderSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    messageId: { type: mongoose.Schema.Types.ObjectId, ref: 'Message', required: true },
    remindAt: { type: Date, required: true },
    // null = still pending. Set atomically when the job claims the reminder.
    sentAt: { type: Date, default: null },
  },
  { timestamps: { createdAt: true, updatedAt: false } }
);

// The job's sweep: "pending reminders that are due".
reminderSchema.index({ sentAt: 1, remindAt: 1 });
// One pending reminder per user per message (re-setting replaces the time).
reminderSchema.index(
  { user: 1, messageId: 1 },
  { unique: true, partialFilterExpression: { sentAt: null } }
);
// Housekeeping: delivered reminders are deleted a week after they fire.
// (TTL ignores documents where sentAt is null, so pending ones are safe.)
reminderSchema.index({ sentAt: 1 }, { expireAfterSeconds: 7 * 24 * 60 * 60 });

export default mongoose.model('Reminder', reminderSchema, 'reminders');
