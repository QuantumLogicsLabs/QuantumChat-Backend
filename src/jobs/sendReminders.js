import Reminder from '../models/Reminder.js';
import Message from '../models/Message.js';
import { notifyUser } from '../services/pushService.js';

const MAX_PER_RUN = 200;

/** Where tapping the push should land (same URL shapes the app already uses). */
function chatUrlFor(message, userId) {
  const q = `?reminder=${message._id}`;
  if (message.group) return `/chat/g/${message.group}${q}`;
  const peer = String(message.from) === String(userId) ? message.to : message.from;
  return `/chat/${peer}${q}`;
}

/**
 * Sends every reminder that has come due. Safe to call from a setInterval
 * AND from the cron endpoint at the same time: each reminder is claimed
 * with an atomic findOneAndUpdate (sentAt: null -> now), so only one caller
 * ever gets a given reminder and nobody is pushed twice.
 */
export async function runReminderJobs() {
  let sent = 0;
  for (let i = 0; i < MAX_PER_RUN; i += 1) {
    const now = new Date();
    const reminder = await Reminder.findOneAndUpdate(
      { sentAt: null, remindAt: { $lte: now } },
      { $set: { sentAt: now } },
      { sort: { remindAt: 1 }, new: true }
    );
    if (!reminder) break;

    try {
      const message = await Message.findById(reminder.messageId).select('from to group');
      if (!message) continue; // message was deleted; nothing to remind about

      // E2E: the push never contains message content, only a generic line.
      // conversationKey is intentionally NOT passed, so a chat the user has
      // since muted doesn't swallow a reminder they explicitly asked for.
      await notifyUser(reminder.user, {
        title: 'QuantumChat',
        body: 'Reminder: you asked to be reminded about a message',
        kind: 'reminder',
        tag: `reminder:${reminder._id}`,
        requireInteraction: true,
        url: chatUrlFor(message, reminder.user),
        data: { messageId: String(message._id) },
      });
      sent += 1;
    } catch (err) {
      console.error('[reminders] failed to send reminder:', err.message);
    }
  }
  return sent;
}
