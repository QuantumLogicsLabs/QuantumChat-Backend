import mongoose from 'mongoose';
import Reminder from '../models/Reminder.js';
import Message from '../models/Message.js';
import Group from '../models/Group.js';

const MIN_LEAD_MS = 30 * 1000; // must be at least 30s in the future
const MAX_LEAD_MS = 365 * 24 * 60 * 60 * 1000; // and at most a year out
const MAX_PENDING_PER_USER = 100;

function toClient(r) {
  return {
    id: String(r._id),
    messageId: String(r.messageId),
    remindAt: r.remindAt.toISOString(),
  };
}

/** The caller must be a party to the DM or a member of the group. */
async function canAccessMessage(userId, message) {
  if (message.group) {
    const group = await Group.findById(message.group).select('members');
    return Boolean(group && group.isMember(userId));
  }
  return [message.from, message.to].some((id) => id && String(id) === String(userId));
}

/** POST /reminders  { messageId, remindAt }  — creates or reschedules. */
export async function createReminder(req, res) {
  try {
    const { messageId, remindAt } = req.body || {};
    if (!mongoose.isValidObjectId(messageId)) {
      return res.status(400).json({ success: false, error: 'Invalid message' });
    }
    const when = new Date(remindAt);
    const lead = when.getTime() - Date.now();
    if (Number.isNaN(when.getTime()) || lead < MIN_LEAD_MS) {
      return res.status(400).json({ success: false, error: 'Pick a time in the future' });
    }
    if (lead > MAX_LEAD_MS) {
      return res.status(400).json({ success: false, error: 'Reminders can be set up to a year ahead' });
    }

    const message = await Message.findById(messageId).select('from to group');
    // Same answer for "missing" and "not yours" so ids can't be probed.
    if (!message || !(await canAccessMessage(req.user._id, message))) {
      return res.status(404).json({ success: false, error: 'Message not found' });
    }

    const existing = await Reminder.findOne({ user: req.user._id, messageId, sentAt: null });
    if (!existing) {
      const pending = await Reminder.countDocuments({ user: req.user._id, sentAt: null });
      if (pending >= MAX_PENDING_PER_USER) {
        return res.status(400).json({ success: false, error: 'Too many pending reminders' });
      }
    }

    const reminder = await Reminder.findOneAndUpdate(
      { user: req.user._id, messageId, sentAt: null },
      { $set: { remindAt: when } },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );
    res.status(201).json({ success: true, data: toClient(reminder) });
  } catch (err) {
    if (err?.code === 11000) {
      return res.status(409).json({ success: false, error: 'Reminder already exists' });
    }
    res.status(500).json({ success: false, error: 'Could not save reminder' });
  }
}

/** GET /reminders[?messageId=]  — the caller's pending reminders. */
export async function listReminders(req, res) {
  try {
    const query = { user: req.user._id, sentAt: null };
    if (req.query.messageId) {
      if (!mongoose.isValidObjectId(req.query.messageId)) {
        return res.status(400).json({ success: false, error: 'Invalid message' });
      }
      query.messageId = req.query.messageId;
    }
    const reminders = await Reminder.find(query).sort({ remindAt: 1 }).limit(MAX_PENDING_PER_USER);
    res.json({ success: true, data: reminders.map(toClient) });
  } catch {
    res.status(500).json({ success: false, error: 'Could not load reminders' });
  }
}

/** DELETE /reminders/:id  — cancel a pending reminder (scoped to the caller). */
export async function deleteReminder(req, res) {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) {
      return res.status(400).json({ success: false, error: 'Invalid reminder' });
    }
    await Reminder.deleteOne({ _id: req.params.id, user: req.user._id, sentAt: null });
    res.json({ success: true, data: { id: req.params.id } });
  } catch {
    res.status(500).json({ success: false, error: 'Could not delete reminder' });
  }
}
