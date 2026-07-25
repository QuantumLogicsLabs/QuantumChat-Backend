import { Router } from 'express';
import {
  sendMessage,
  getConversation,
  markConversationRead,
  deleteMessage,
  reactToMessage,
  editMessage,
  publishQuantumAIDirectResponse,
  checkForwardAllowed,
} from '../controllers/messageController.js';
import { requireAuth } from '../middleware/auth.js';
import { apiLimiter } from '../middleware/rateLimiter.js';

const router = Router();

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
