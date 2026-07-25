import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import { groupPhotoUpload } from '../middleware/upload.js';
import { apiLimiter } from '../middleware/rateLimiter.js';
import {
  createGroup,
  listGroups,
  getGroup,
  sendGroupMessage,
  getGroupMessages,
  renameGroup,
  updateGroup,
  addMembers,
  removeMember,
  deleteGroup,
  uploadGroupPhoto,
  getGroupPhoto,
  setInviteLink,
  previewInvite,
  joinViaInvite,
  addAdmin,
  removeAdmin,
  pinMessage,
  unpinMessage,
  votePoll,
  publishQuantumAIGroupResponse,
  discoverGroups,
  joinPublicGroup,
  createJoinRequest,
  listJoinRequests,
  acceptJoinRequest,
  rejectJoinRequest,
} from '../controllers/groupController.js';

const router = Router();

// Rate-limit before auth so CodeQL js/missing-rate-limiting sees a limiter
// on authorization/DB route handlers (requireAuth touches the user store).
router.use(apiLimiter);
router.use(requireAuth);

router.get('/', listGroups);
router.post('/', createGroup);

router.get('/discover', discoverGroups);

router.get('/invite/:code', previewInvite);
router.post('/join', joinViaInvite);
router.post('/join/:code', joinViaInvite);

router.post('/:id/join', joinPublicGroup);
router.post('/:id/join-requests', createJoinRequest);
router.get('/:id/join-requests', listJoinRequests);
router.post('/:id/join-requests/:userId/accept', acceptJoinRequest);
router.post('/:id/join-requests/:userId/reject', rejectJoinRequest);

router.get('/:id', getGroup);
router.patch('/:id', updateGroup);
router.patch('/:id/name', renameGroup);
router.delete('/:id', deleteGroup);

router.post('/:id/photo', groupPhotoUpload.single('photo'), uploadGroupPhoto);
router.get('/:id/photo', getGroupPhoto);

router.post('/:id/invite', setInviteLink);

router.post('/:id/members', addMembers);
router.delete('/:id/members/:memberId', removeMember);

router.post('/:id/admins/:memberId', addAdmin);
router.delete('/:id/admins/:memberId', removeAdmin);

router.post('/:id/pins/:messageId', pinMessage);
router.delete('/:id/pins/:messageId', unpinMessage);

router.get('/:groupId/messages', getGroupMessages);
router.post('/:groupId/messages', sendGroupMessage);
router.post('/:groupId/quantum-ai-response', publishQuantumAIGroupResponse);

router.post('/messages/:messageId/poll-vote', votePoll);

export default router;
