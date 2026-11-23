import Reminder from '../models/Reminder.js';
import Message from '../models/Message.js';
import User from '../models/User.js';
import Group from '../models/Group.js';
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
 * Builds the push text. Messages are end-to-end encrypted, so the server can
 * NOT put the message body in the push; it can only say who the message is
 * from (the server already knows who talks to whom). The decrypted text is
 * shown inside the app when the user taps the notification.
 */
async function describeMessage(message, userId) {
  const mine = String(message.from) === String(userId);
  const otherId = mine ? message.to : message.from;

  const [other, group] = await Promise.all([
    otherId ? User.findById(otherId).select('username').lean() : null,
    message.group ? Group.findById(message.group).select('name').lean() : null,
  ]);
  const sender = other?.username || 'someone';

  if (group) {
    const where = group.name ? ` in ${group.name}` : ' in a group';
    return mine
      ? `Reminder: your message${where}`
      : `Reminder: message from ${message.fromUsername || sender}${where}`;
  }
  return mine ? `Reminder: your message to ${sender}` : `Reminder: message from ${sender}`;
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

      const msgObj = message.toObject();
      if (msgObj.group) {
        // For group messages `from` is the sender; resolve the name directly.
        const senderDoc = await User.findById(msgObj.from).select('username').lean();
        msgObj.fromUsername = senderDoc?.username;
      }

      // conversationKey is intentionally NOT passed, so a chat the user has
      // since muted doesn't swallow a reminder they explicitly asked for.
      await notifyUser(reminder.user, {
        title: 'QuantumChat',
        body: await describeMessage(msgObj, reminder.user),
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
