import { Router } from 'express';
import {
  sendMessage,
  getConversation,
  syncMessages,
  markConversationRead,
  deleteMessage,
  reactToMessage,
  editMessage,
  publishQuantumAIDirectResponse,
  checkForwardAllowed,
  openViewOnce,
  upsertTranscriptState,
  getMessageInfo,
  getImportantMessages,
  markMessageImportant,
  unmarkMessageImportant,
} from '../controllers/messageController.js';
import { requireAuthLean } from '../middleware/auth.js';
import { readVaultUnlock } from '../middleware/vaultAuth.js';
import { apiLimiter, syncLimiter } from '../middleware/rateLimiter.js';
const router = Router();

// Sub-router for /sync so syncLimiter is applied via a bare router-level
// .use() (no path, before its one route) — the same shape apiLimiter uses
// below, which CodeQL's rate-limiting check reliably recognizes. Applying
// syncLimiter inline or on a path-scoped .use() on the main router wasn't
// picked up by CodeQL even though it works correctly at runtime.
const syncRouter = Router();
// apiLimiter (IP-keyed) must run before requireAuth's DB lookup — this is
// what CodeQL's "missing rate limiting" check requires: nothing gated the
// requireAuth step itself. syncLimiter stays after requireAuth since it's
// keyed on req.user._id.
syncRouter.use(apiLimiter,requireAuthLean, readVaultUnlock, syncLimiter);
syncRouter.get('/', syncMessages);

// Declared before the router-level middleware and before '/:userId', for two
// reasons: getConversation would otherwise match "sync" as a user id and 400,
// and syncLimiter keys on req.user._id so requireAuth has to run first — the
// opposite of the apiLimiter-then-requireAuth order used below.
router.use('/sync', syncRouter);

router.use(apiLimiter);
router.use(requireAuthLean);
router.use(readVaultUnlock);
router.post('/', sendMessage);
router.post('/quantum-ai-response', publishQuantumAIDirectResponse);
// Must stay above GET /:userId — otherwise "important" is parsed as a peer id
// and the client shows stacked "Invalid user id" toasts on every chat load.
router.get('/important', getImportantMessages);
router.get('/:messageId/forward-check', checkForwardAllowed);
router.post('/:messageId/view-once', openViewOnce);
router.post('/:messageId/transcription', upsertTranscriptState);
router.get('/:messageId/info', getMessageInfo);
router.post('/:messageId/important', markMessageImportant);
router.delete('/:messageId/important', unmarkMessageImportant);
router.get('/:userId', getConversation);
router.post('/:userId/read', markConversationRead);
router.patch('/:messageId', editMessage);
router.delete('/:messageId', deleteMessage);
router.post('/:messageId/reactions', reactToMessage);

export default router;