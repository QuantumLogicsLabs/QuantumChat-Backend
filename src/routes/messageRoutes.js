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
} from '../controllers/messageController.js';
import { requireAuth } from '../middleware/auth.js';
import { apiLimiter, syncLimiter } from '../middleware/rateLimiter.js';

const router = Router();

// Declared before the router-level middleware and before '/:userId', for two
// reasons: getConversation would otherwise match "sync" as a user id and 400,
// and syncLimiter keys on req.user._id so requireAuth has to run first — the
// opposite of the apiLimiter-then-requireAuth order used below.
router.get('/sync', requireAuth, syncLimiter, syncMessages);

router.use(apiLimiter);
router.use(requireAuth);
router.post('/', sendMessage);
router.post('/quantum-ai-response', publishQuantumAIDirectResponse);
router.get('/:messageId/forward-check', checkForwardAllowed);
router.get('/:userId', getConversation);
router.post('/:userId/read', markConversationRead);
router.patch('/:messageId', editMessage);
router.delete('/:messageId', deleteMessage);
router.post('/:messageId/reactions', reactToMessage);

export default router;
