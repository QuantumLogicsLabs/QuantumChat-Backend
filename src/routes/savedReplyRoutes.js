import { Router } from 'express';
import {
  createSavedReply,
  deleteSavedReply,
  listSavedReplies,
  updateSavedReply,
} from '../controllers/savedReplyController.js';
import { requireAuthLean } from '../middleware/auth.js';
import { apiLimiter } from '../middleware/rateLimiter.js';

const router = Router();
router.use(apiLimiter);
router.use(requireAuthLean);

router.get('/', listSavedReplies);
router.post('/', createSavedReply);
router.put('/:id', updateSavedReply);
router.delete('/:id', deleteSavedReply);

export default router;
