import jwt from 'jsonwebtoken';

/**
 * Non-blocking: sets req.chatLockUnlocked = true only if a valid, unexpired
 * Chat Lock token for the *current authenticated user* is present in the
 * x-chat-lock-token header. Never rejects — routes decide what to do with the
 * flag (e.g. refuse to return history for a locked conversation).
 */
export function readChatUnlock(req, _res, next) {
  req.chatLockUnlocked = false;
  try {
    const token = req.headers['x-chat-lock-token'];
    if (!token || !req.user) return next();
    const payload = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
    if (payload.scope === 'chatlock' && String(payload.sub) === String(req.user._id)) {
      req.chatLockUnlocked = true;
    }
  } catch {
    // invalid/expired token -> stays locked, no error surfaced
  }
  next();
}
