import { Router } from 'express';
import { uploadAttachment, downloadAttachment } from '../controllers/attachmentController.js';
import { requireAuth } from '../middleware/auth.js';
import { apiLimiter } from '../middleware/rateLimiter.js';
import { upload } from '../middleware/upload.js';

const router = Router();

router.use(apiLimiter);
router.use(requireAuth);
router.post(
  '/',
  upload.fields([
    { name: 'file', maxCount: 1 },
    { name: 'senderFile', maxCount: 1 },
  ]),
  uploadAttachment
);
router.get('/:id/raw', downloadAttachment);

export default router;
