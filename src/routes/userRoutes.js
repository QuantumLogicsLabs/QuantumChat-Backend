import { Router } from 'express';
import { createAiCapsule, listAiCapsules } from '../controllers/capsuleController.js';
import {
  createChatFolder,
  deleteChatFolder,
  listChatFolders,
  setChatFolderMembership,
  updateChatFolder,
} from '../controllers/chatFolderController.js';
import {
  disableChatLock,
  getChatLockStatus,
  lockChat,
  setChatLockPin,
  unlockChat,
  verifyChatLockPin,
} from '../controllers/chatLockController.js';
import {
  approveLinkRequest,
  createLinkRequest,
  rejectLinkRequest,
  sendLinkEmail,
} from '../controllers/deviceLinkController.js';
import {
  getPushVapidPublicKey,
  subscribePush,
  unsubscribePush,
} from '../controllers/pushController.js';
import { listSessions, revokeSession } from '../controllers/sessionController.js';
import {
  acceptFriendRequest,
  blockUser,
  cancelFriendRequest,
  clearConversation,
  declineFriendRequest,
  deleteAccount,
  deleteAvatar,
  discoverUsers,
  exportAccountData,
  getAvatar,
  getMe,
  getMyPublicKeys,
  getMyReferrals,
  getNotificationSettings,
  getUser,
  listBlockedUsers,
  listFriendRequests,
  listFriends,
  listUsers,
  lookupContact,
  muteChat,
  removeFriend,
  sendFriendRequest,
  unblockUser,
  undoClearConversation,
  unmuteChat,
  updateLanguage,
  updateNotificationSettings,
  updatePrivacy,
  updateProfile,
  updatePublicKeys,
  uploadAvatar,
} from '../controllers/userController.js';
import {
  disableVault,
  getVaultStatus,
  setVaultPassword,
  unlockVault,
} from '../controllers/vaultAuthController.js';
import { deleteVault, getVault, putVault } from '../controllers/vaultController.js';
import {
  addToVault,
  getPeerVaultDecoyStatus,
  listVaultedPeerIds,
  removeFromVault,
} from '../controllers/vaultMembershipController.js';
import { requireAuth } from '../middleware/auth.js';
import { apiLimiter, chatLockLimiter, contactLookupLimiter, vaultAuthLimiter } from '../middleware/rateLimiter.js';
import { avatarUpload } from '../middleware/upload.js';
import { readVaultUnlock } from '../middleware/vaultAuth.js';

const router = Router();

router.use(apiLimiter);
router.use(requireAuth);
router.get('/', listUsers);
router.get('/me', getMe);
router.get('/me/public-keys', getMyPublicKeys);
router.patch('/me', updateProfile);
router.patch('/me/language', updateLanguage);
router.patch('/me/privacy', updatePrivacy);
router.patch('/me/public-keys', updatePublicKeys);
router.get('/me/notification-settings', getNotificationSettings);
router.put('/me/notification-settings', updateNotificationSettings);
router.post('/me/mute', muteChat);
router.post('/me/unmute', unmuteChat);
router.get('/me/chat-folders', listChatFolders);
router.post('/me/chat-folders', createChatFolder);
router.patch('/me/chat-folders/:folderId', updateChatFolder);
router.put('/me/chat-folders/:folderId/chats', setChatFolderMembership);
router.delete('/me/chat-folders/:folderId', deleteChatFolder);
router.post('/me/clear-chat', clearConversation);
router.post('/me/clear-chat/undo', undoClearConversation);
router.get('/me/blocked', listBlockedUsers);
router.get('/me/export', exportAccountData);
router.delete('/me', deleteAccount);
router.post('/me/avatar', avatarUpload.single('avatar'), uploadAvatar);
router.delete('/me/avatar', deleteAvatar);
router.get('/me/sessions', listSessions);
router.post('/me/sessions/link', createLinkRequest);
router.post('/me/sessions/link/approve', approveLinkRequest);
router.post('/me/sessions/link/reject', rejectLinkRequest);
router.post('/me/sessions/link/email', sendLinkEmail);
router.delete('/me/sessions/:sessionId', revokeSession);
router.get('/me/referrals', getMyReferrals);
router.get('/me/vault', getVault);
router.put('/me/vault', putVault);
router.delete('/me/vault', deleteVault);
router.get('/me/chat-lock/status', getChatLockStatus);
router.post('/me/chat-lock/set-pin', chatLockLimiter, setChatLockPin);
router.post('/me/chat-lock/verify', chatLockLimiter, verifyChatLockPin);
router.post('/me/chat-lock/disable', chatLockLimiter, disableChatLock);
router.post('/me/chat-lock/lock', lockChat);
router.post('/me/chat-lock/unlock', chatLockLimiter, unlockChat);
router.post('/me/ai-capsules', createAiCapsule);
router.get('/me/ai-capsules', listAiCapsules);
router.get('/me/push/vapid-public-key', getPushVapidPublicKey);
router.post('/me/push/subscribe', subscribePush);
router.delete('/me/push/subscribe', unsubscribePush);
// Static collection routes must be registered before /:id so words like
// "friends" / "discover" are never parsed as user ids.
router.get('/discover', discoverUsers);
router.get('/lookup', contactLookupLimiter, lookupContact);
router.get('/friends', listFriends);
router.get('/friend-requests', listFriendRequests);
router.post('/friend-requests', sendFriendRequest);
router.delete('/friend-requests/:id', cancelFriendRequest);
router.post('/friend-requests/:id/accept', acceptFriendRequest);
router.post('/friend-requests/:id/decline', declineFriendRequest);
router.delete('/friends/:id', removeFriend);
router.post('/:id/block', blockUser);
router.delete('/:id/block', unblockUser);
router.get('/:id/avatar', getAvatar);
router.get('/:id', getUser);
router.get('/me/vault-lock/status', getVaultStatus);
router.post('/me/vault-lock/set-password', vaultAuthLimiter, setVaultPassword);
router.post('/me/vault-lock/unlock', vaultAuthLimiter, unlockVault);
router.post('/me/vault-lock/disable', vaultAuthLimiter, disableVault);

router.get('/me/vault-lock/members', listVaultedPeerIds);
router.post('/me/vault-lock/members', addToVault);
router.delete('/me/vault-lock/members/:peerId', removeFromVault);
router.get('/me/vault-lock/members/:peerId/decoy-status', readVaultUnlock, getPeerVaultDecoyStatus);
export default router;
