import mongoose from 'mongoose';
import SavedReply from '../models/SavedReply.js';

const SHORTCUT_PATTERN = /^\/[a-zA-Z0-9][a-zA-Z0-9_-]{0,39}$/;

function validateInput(body = {}) {
  const shortcut = typeof body.shortcut === 'string' ? body.shortcut.trim() : '';
  const message = typeof body.message === 'string' ? body.message.trim() : '';
  if (!shortcut || !SHORTCUT_PATTERN.test(shortcut)) {
    return { error: 'Shortcut must start with / and contain only letters, numbers, _ or -' };
  }
  if (!message) return { error: 'Message cannot be empty' };
  return { shortcut, message, normalizedShortcut: shortcut.toLowerCase() };
}

function duplicateError(err) {
  return err?.code === 11000 && err?.keyPattern?.normalizedShortcut;
}

export async function listSavedReplies(req, res) {
  try {
    const replies = await SavedReply.find({ owner: req.user._id }).sort({ shortcut: 1 });
    res.json({ success: true, data: replies.map((reply) => reply.toPublicJSON()) });
  } catch (err) {
    console.error('List saved replies failed:', err);
    res.status(500).json({ success: false, error: 'Could not load saved replies' });
  }
}

export async function createSavedReply(req, res) {
  const input = validateInput(req.body);
  if (input.error) return res.status(400).json({ success: false, error: input.error });
  try {
    const reply = await SavedReply.create({ ...input, owner: req.user._id });
    res.status(201).json({ success: true, data: reply.toPublicJSON() });
  } catch (err) {
    if (duplicateError(err)) {
      return res.status(409).json({ success: false, error: 'That shortcut already exists' });
    }
    console.error('Create saved reply failed:', err);
    res.status(500).json({ success: false, error: 'Could not create saved reply' });
  }
}

export async function updateSavedReply(req, res) {
  if (!mongoose.isValidObjectId(req.params.id)) {
    return res.status(400).json({ success: false, error: 'Invalid saved reply id' });
  }
  const input = validateInput(req.body);
  if (input.error) return res.status(400).json({ success: false, error: input.error });
  try {
    const reply = await SavedReply.findOneAndUpdate(
      { _id: req.params.id, owner: req.user._id },
      input,
      { new: true, runValidators: true }
    );
    if (!reply) return res.status(404).json({ success: false, error: 'Saved reply not found' });
    res.json({ success: true, data: reply.toPublicJSON() });
  } catch (err) {
    if (duplicateError(err)) {
      return res.status(409).json({ success: false, error: 'That shortcut already exists' });
    }
    console.error('Update saved reply failed:', err);
    res.status(500).json({ success: false, error: 'Could not update saved reply' });
  }
}

export async function deleteSavedReply(req, res) {
  if (!mongoose.isValidObjectId(req.params.id)) {
    return res.status(400).json({ success: false, error: 'Invalid saved reply id' });
  }
  try {
    const reply = await SavedReply.findOneAndDelete({ _id: req.params.id, owner: req.user._id });
    if (!reply) return res.status(404).json({ success: false, error: 'Saved reply not found' });
    res.json({ success: true, data: { id: String(reply._id) } });
  } catch (err) {
    console.error('Delete saved reply failed:', err);
    res.status(500).json({ success: false, error: 'Could not delete saved reply' });
  }
}
