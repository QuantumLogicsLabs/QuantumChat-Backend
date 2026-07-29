import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import { callSignalLimiter } from '../middleware/rateLimiter.js';
import {
  createCallSignal,
  listCallSignals,
} from '../controllers/callSignalController.js';

const router = Router();

router.use(callSignalLimiter);
router.use(requireAuth);
router.get('/', listCallSignals);
router.post('/', createCallSignal);

export default router;
