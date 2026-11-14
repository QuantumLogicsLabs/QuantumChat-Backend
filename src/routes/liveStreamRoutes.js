import { Router } from 'express';
import {
  endLiveStream,
  getLiveStream,
  heartbeatLiveStream,
  inviteToLiveStream,
  joinLiveStream,
  leaveLiveStream,
  listLiveStreams,
  removeLiveViewer,
  setLiveRecordingDecision,
  startLiveStream,
} from '../controllers/liveStreamController.js';
import { requireAuth } from '../middleware/auth.js';
import { liveStreamGatewayLimiter, liveStreamLimiter } from '../middleware/rateLimiter.js';

const router = Router();

// Same layering as callSignalRoutes: IP gate before the auth DB lookup,
// then the per-user budget once req.user exists.
router.use(liveStreamGatewayLimiter);
router.use(requireAuth);
router.use(liveStreamLimiter);

router.get('/', listLiveStreams);
router.post('/', startLiveStream);
router.get('/:id', getLiveStream);
router.post('/:id/join', joinLiveStream);
router.post('/:id/leave', leaveLiveStream);
router.post('/:id/heartbeat', heartbeatLiveStream);
router.post('/:id/invite', inviteToLiveStream);
router.post('/:id/remove', removeLiveViewer);
router.post('/:id/end', endLiveStream);
router.post('/:id/recording', setLiveRecordingDecision);

export default router;
