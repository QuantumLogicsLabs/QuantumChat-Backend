import { Router } from 'express';
import {
  listUsers,
  getUser,
  updatePublicKeys,
  updateProfile,
  blockUser,
  unblockUser,
  listBlockedUsers,
  uploadAvatar,
  deleteAvatar,
  getAvatar,
  exportAccountData,
  deleteAccount,
} from '../controllers/userController.js';
import {
  getPushVapidPublicKey,
  subscribePush,
  unsubscribePush,
} from '../controllers/pushController.js';
import { listSessions, revokeSession } from '../controllers/sessionController.js';
import { getVault, putVault, deleteVault } from '../controllers/vaultController.js';
import { createAiCapsule, listAiCapsules } from '../controllers/capsuleController.js';
import { requireAuth } from '../middleware/auth.js';
import { avatarUpload } from '../middleware/upload.js';
import { apiLimiter } from '../middleware/rateLimiter.js';

const router = Router();

router.use(apiLimiter);
router.use(requireAuth);
router.get('/', listUsers);
router.patch('/me', updateProfile);
router.patch('/me/public-keys', updatePublicKeys);
router.get('/me/blocked', listBlockedUsers);
router.get('/me/export', exportAccountData);
router.delete('/me', deleteAccount);
router.post('/me/avatar', avatarUpload.single('avatar'), uploadAvatar);
router.delete('/me/avatar', deleteAvatar);
router.get('/me/sessions', listSessions);
router.delete('/me/sessions/:sessionId', revokeSession);
router.get('/me/vault', getVault);
router.put('/me/vault', putVault);
router.delete('/me/vault', deleteVault);
router.post('/me/ai-capsules', createAiCapsule);
router.get('/me/ai-capsules', listAiCapsules);
router.get('/me/push/vapid-public-key', getPushVapidPublicKey);
router.post('/me/push/subscribe', subscribePush);
router.delete('/me/push/subscribe', unsubscribePush);
router.post('/:id/block', blockUser);
router.delete('/:id/block', unblockUser);
router.get('/:id/avatar', getAvatar);
router.get('/:id', getUser);

export default router;
