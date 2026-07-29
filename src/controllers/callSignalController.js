import CallSignal from '../models/CallSignal.js';
import User from '../models/User.js';
import { isSealedEnvelope } from '../utils/callEnvelope.js';
import { toObjectId } from '../utils/toObjectId.js';

const ALLOWED_EVENTS = new Set([
  'call:invite',
  'call:accept',
  'call:reject',
  'call:hangup',
  'call:offer',
  'call:answer',
  'call:ice',
]);

function toClientSignal(signal) {
  return {
    id: signal._id,
    from: signal.from,
    callId: signal.callId,
    event: signal.event,
    envelope: signal.envelope,
    createdAt: signal.createdAt,
  };
}

/**
 * Stores only an opaque X5 envelope. This is a fallback transport for
 * serverless deployments where Socket.IO cannot keep a connection alive.
 */
export async function createCallSignal(req, res) {
  try {
    const { to, callId, event, envelope } = req.body || {};
    const recipientId = toObjectId(to);
    if (!recipientId || recipientId.equals(req.user._id)) {
      return res.status(400).json({ success: false, error: 'Invalid call recipient' });
    }
    if (!ALLOWED_EVENTS.has(event)) {
      return res.status(400).json({ success: false, error: 'Invalid call signal event' });
    }
    if (typeof callId !== 'string' || !callId.trim() || callId.length > 128) {
      return res.status(400).json({ success: false, error: 'Invalid call id' });
    }
    if (!isSealedEnvelope(envelope)) {
      return res.status(400).json({ success: false, error: 'Call signal must be X5 sealed' });
    }

    const recipientExists = await User.exists({ _id: recipientId });
    if (!recipientExists) {
      return res.status(404).json({ success: false, error: 'Call recipient not found' });
    }

    const signal = await CallSignal.create({
      from: req.user._id,
      to: recipientId,
      callId: callId.trim(),
      event,
      envelope: {
        ciphertext: envelope.ciphertext,
        nonce: envelope.nonce,
        ephemeralPublicKey: String(envelope.ephemeralPublicKey).toLowerCase(),
        targetPublicKey: String(envelope.targetPublicKey).toLowerCase(),
      },
    });

    return res.status(201).json({
      success: true,
      data: { id: signal._id, createdAt: signal.createdAt },
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
}

export async function listCallSignals(req, res) {
  try {
    const requestedAfter = new Date(req.query.after || Date.now() - 5_000);
    const oldestAllowed = Date.now() - 2 * 60 * 1000;
    const after = Number.isNaN(requestedAfter.getTime())
      ? new Date(Date.now() - 5_000)
      : new Date(Math.max(requestedAfter.getTime(), oldestAllowed));

    // Use $gte deliberately. Signals sharing the cursor millisecond are
    // returned again and safely de-duplicated by id on the client.
    const signals = await CallSignal.find({
      to: req.user._id,
      createdAt: { $gte: after },
      expiresAt: { $gt: new Date() },
    })
      .sort({ createdAt: 1, _id: 1 })
      .limit(200)
      .lean();

    const cursor = signals.length
      ? signals[signals.length - 1].createdAt.toISOString()
      : after.toISOString();

    return res.json({
      success: true,
      data: { signals: signals.map(toClientSignal), cursor },
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
}
