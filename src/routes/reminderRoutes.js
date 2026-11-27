import { Router } from 'express';
import { requireAuthLean } from '../middleware/auth.js';
import { apiLimiter } from '../middleware/rateLimiter.js';
import { createReminder, listReminders, deleteReminder } from '../controllers/reminderController.js';

const router = Router();

router.use(apiLimiter);
router.use(requireAuthLean);
router.post('/', createReminder);
router.get('/', listReminders);
router.delete('/:id', deleteReminder);

export default router;
