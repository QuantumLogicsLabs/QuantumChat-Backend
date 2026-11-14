import Group from '../models/Group.js';
import LiveStream, {
  LIVE_AUDIENCE_TYPES,
  LIVE_HEARTBEAT_STALE_MS,
  LIVE_TITLE_MAX,
} from '../models/LiveStream.js';
import User from '../models/User.js';
import { createNotification } from '../services/notificationService.js';
import { canUserInviteToCall } from '../utils/callEnvelope.js';
import {
  canViewLiveStream,
  expireStaleLiveStreams,
  resolveLiveAudienceIds,
} from '../utils/liveAccess.js';
import { toObjectId } from '../utils/toObjectId.js';

const ACCESS_FIELDS = '_id username displayName friends blockedUsers avatarPath publicKeys';
const MAX_LIST_IDS = 200;
// A viewer who just joined hasn't finished WebRTC setup yet, so the host's
// heartbeat won't list them as connected — keep them admitted for this long.
const JOIN_GRACE_MS = 30_000;
const NOTIFICATION_TTL_MS = 24 * 60 * 60 * 1000;

function userSummary(u) {
  if (!u) return null;
  return {
    id: String(u._id),
    username: u.username,
    displayName: u.displayName || '',
    hasAvatar: Boolean(u.avatarPath),
  };
}

function toObjectIdList(raw) {
  if (!Array.isArray(raw)) return [];
  const seen = new Set();
  const out = [];
  for (const value of raw.slice(0, MAX_LIST_IDS)) {
    const oid = toObjectId(value);
    if (oid && !seen.has(String(oid))) {
      seen.add(String(oid));
      out.push(oid);
    }
  }
  return out;
}

function sanitizeTitle(raw) {
  return String(raw || '')
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .trim()
    .slice(0, LIVE_TITLE_MAX);
}

function toPublicStream(stream, viewerId, { host, group } = {}) {
  const isHost = String(stream.host?._id || stream.host) === String(viewerId);
  const base = {
    id: String(stream._id),
    host: userSummary(host || stream.host),
    title: stream.title || '',
    audienceType: stream.audience?.type || 'friends',
    group: group ? { id: String(group._id), name: group.name } : null,
    status: stream.status,
    startedAt: stream.startedAt,
    endedAt: stream.endedAt,
    viewerCount: (stream.viewers || []).length,
    peakViewers: stream.peakViewers || 0,
    isHost,
  };
  if (!isHost) return base;
  return {
    ...base,
    totalViewers: stream.totalViewers || 0,
    endReason: stream.endReason,
    audience: {
      type: stream.audience?.type || 'friends',
      groupId: stream.audience?.group ? String(stream.audience.group) : null,
      users: (stream.audience?.users || []).map(String),
      hiddenFrom: (stream.audience?.hiddenFrom || []).map(String),
    },
    invited: (stream.invited || []).map(String),
    removed: (stream.removed || []).map(String),
    recording: {
      enabled: Boolean(stream.recording?.enabled),
      decision: stream.recording?.decision || 'none',
    },
  };
}

async function loadGroupForStream(stream) {
  if (stream.audience?.type !== 'group' || !stream.audience.group) return null;
  return Group.findById(stream.audience.group).select('_id name').lean();
}

async function hostViewerDetails(stream) {
  const ids = (stream.viewers || []).map((v) => v.user);
  if (!ids.length) return [];
  const users = await User.find({ _id: { $in: ids } })
    .select('_id username displayName avatarPath publicKeys')
    .lean();
  const byId = new Map(users.map((u) => [String(u._id), u]));
  return stream.viewers
    .map((v) => {
      const u = byId.get(String(v.user));
      if (!u) return null;
      return {
        ...userSummary(u),
        publicKeys: (u.publicKeys || []).map((k) => String(k).toLowerCase()),
        joinedAt: v.joinedAt,
      };
    })
    .filter(Boolean);
}

function emitToUsers(io, userIds, event, payload) {
  if (!io) return;
  for (const id of userIds) io.to(String(id)).emit(event, payload);
}

async function notifyAudience(stream, host, io) {
  const audienceIds = await resolveLiveAudienceIds(stream, host);
  if (!audienceIds.length) return;

  const optedIn = await User.find({
    _id: { $in: audienceIds },
    'notificationSettings.liveNotifications': { $ne: false },
  })
    .select('_id')
    .lean();

  const hostName = host.displayName || host.username || 'A friend';
  const streamId = String(stream._id);
  const publicStream = toPublicStream(stream, null, { host });
  const expiresAt = new Date(Date.now() + NOTIFICATION_TTL_MS);
  const body = stream.title ? `${hostName} is live: ${stream.title}` : `${hostName} started a live video`;

  emitToUsers(io, audienceIds, 'live:started', publicStream);
  await Promise.all(
    optedIn.map((u) =>
      createNotification({
        recipient: u._id,
        actor: host._id,
        type: 'LIVE_STARTED',
        entityType: 'live',
        entityId: streamId,
        metadata: { streamId, title: stream.title || '' },
        expiresAt,
        io,
        push: {
          title: 'QuantumChat',
          body,
          kind: 'live',
          tag: `live:${streamId}`,
          url: `/chat/live/${streamId}`,
          data: { streamId },
        },
      }).catch(() => null)
    )
  );
}

async function findLiveStreamOr404(req, res) {
  const id = toObjectId(req.params.id);
  if (!id) {
    res.status(400).json({ success: false, error: 'Invalid live stream id' });
    return null;
  }
  const stream = await LiveStream.findById(id);
  if (!stream) {
    res.status(404).json({ success: false, error: 'Live stream not found' });
    return null;
  }
  if (stream.status === 'live' && Date.now() - stream.lastHeartbeatAt.getTime() > LIVE_HEARTBEAT_STALE_MS) {
    stream.markEnded('timeout');
    await stream.save();
  }
  return stream;
}

function requireHost(stream, req, res) {
  if (String(stream.host) !== String(req.user._id)) {
    res.status(403).json({ success: false, error: 'Only the host can do that' });
    return false;
  }
  return true;
}

async function endStream(stream, reason, io) {
  const viewerIds = (stream.viewers || []).map((v) => String(v.user));
  stream.markEnded(reason);
  await stream.save();
  emitToUsers(io, [String(stream.host), ...viewerIds], 'live:ended', {
    id: String(stream._id),
    reason,
  });
}

export async function startLiveStream(req, res) {
  try {
    const { title, audience = {}, record } = req.body || {};
    const type = LIVE_AUDIENCE_TYPES.includes(audience.type) ? audience.type : 'friends';
    const host = await User.findById(req.user._id).select(ACCESS_FIELDS);
    const hostFriends = new Set((host.friends || []).map(String));

    let groupId = null;
    let users = [];
    if (type === 'group') {
      groupId = toObjectId(audience.groupId);
      const group = groupId ? await Group.findById(groupId).select('members') : null;
      if (!group || !group.isMember(host._id)) {
        return res.status(403).json({ success: false, error: 'You can only go live to a group you belong to' });
      }
    }
    if (type === 'custom') {
      // A custom audience is picked from the host's friends.
      users = toObjectIdList(audience.userIds).filter((id) => hostFriends.has(String(id)));
      if (!users.length) {
        return res.status(400).json({ success: false, error: 'Pick at least one friend for a custom audience' });
      }
    }
    const hiddenFrom = type === 'custom' ? [] : toObjectIdList(audience.hiddenFrom);

    // One live stream per host: starting a new one ends any previous one
    // (e.g. a tab that crashed before it could end cleanly).
    const io = req.app.get('io');
    const previous = await LiveStream.find({ host: host._id, status: 'live' });
    for (const old of previous) await endStream(old, 'replaced', io);

    const stream = await LiveStream.create({
      host: host._id,
      title: sanitizeTitle(title),
      audience: { type, group: groupId, users, hiddenFrom },
      recording: { enabled: record === true, decision: 'none' },
    });

    notifyAudience(stream, host, io).catch((err) =>
      console.warn('[live] audience notification failed:', err.message)
    );

    const group = await loadGroupForStream(stream);
    return res.status(201).json({
      success: true,
      data: { stream: toPublicStream(stream, host._id, { host, group }) },
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Could not start live stream' });
  }
}

export async function listLiveStreams(req, res) {
  try {
    await expireStaleLiveStreams();
    const me = await User.findById(req.user._id).select(ACCESS_FIELDS).lean();
    const myGroups = await Group.find({ members: me._id }).select('_id').lean();
    const cutoff = new Date(Date.now() - LIVE_HEARTBEAT_STALE_MS);

    const candidates = await LiveStream.find({
      status: 'live',
      lastHeartbeatAt: { $gte: cutoff },
      removed: { $ne: me._id },
      $or: [
        { host: me._id },
        { 'audience.type': 'friends', host: { $in: me.friends || [] } },
        { 'audience.type': 'group', 'audience.group': { $in: myGroups.map((g) => g._id) } },
        { 'audience.type': 'custom', 'audience.users': me._id },
        { invited: me._id },
      ],
    })
      .sort({ startedAt: -1 })
      .limit(50);

    const hostIds = [...new Set(candidates.map((s) => String(s.host)))];
    const hosts = await User.find({ _id: { $in: hostIds } }).select(ACCESS_FIELDS).lean();
    const hostById = new Map(hosts.map((h) => [String(h._id), h]));

    const visible = [];
    for (const stream of candidates) {
      const host = hostById.get(String(stream.host));
      if (!host || !(await canViewLiveStream(stream, host, me))) continue;
      const group = await loadGroupForStream(stream);
      visible.push(toPublicStream(stream, me._id, { host, group }));
    }
    return res.json({ success: true, data: { streams: visible } });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Could not load live streams' });
  }
}

export async function getLiveStream(req, res) {
  try {
    const stream = await findLiveStreamOr404(req, res);
    if (!stream) return undefined;
    const [host, me] = await Promise.all([
      User.findById(stream.host).select(ACCESS_FIELDS).lean(),
      User.findById(req.user._id).select(ACCESS_FIELDS).lean(),
    ]);
    const isHost = String(stream.host) === String(me._id);
    // Ended streams stay readable to past viewers' clients only as a bare
    // "ended" status; everything else needs current access.
    if (!isHost && stream.status === 'live' && !(await canViewLiveStream(stream, host, me))) {
      return res.status(403).json({ success: false, error: 'You are not in this live stream’s audience' });
    }
    if (!isHost && stream.status !== 'live') {
      return res.json({ success: true, data: { stream: { id: String(stream._id), status: stream.status } } });
    }
    const group = await loadGroupForStream(stream);
    return res.json({ success: true, data: { stream: toPublicStream(stream, me._id, { host, group }) } });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Could not load live stream' });
  }
}

export async function joinLiveStream(req, res) {
  try {
    const stream = await findLiveStreamOr404(req, res);
    if (!stream) return undefined;
    if (stream.status !== 'live') {
      return res.status(410).json({ success: false, error: 'This live stream has ended' });
    }
    if (String(stream.host) === String(req.user._id)) {
      return res.status(400).json({ success: false, error: 'You are hosting this live stream' });
    }
    const [host, me] = await Promise.all([
      User.findById(stream.host).select(ACCESS_FIELDS).lean(),
      User.findById(req.user._id).select(ACCESS_FIELDS).lean(),
    ]);
    if (!(await canViewLiveStream(stream, host, me))) {
      return res.status(403).json({ success: false, error: 'You are not in this live stream’s audience' });
    }

    // Atomic add so two near-simultaneous joins can't both see "absent" and
    // double-count, then refresh the counters from the stored array.
    const added = await LiveStream.updateOne(
      { _id: stream._id, status: 'live', 'viewers.user': { $ne: me._id } },
      { $push: { viewers: { user: me._id, joinedAt: new Date() } }, $inc: { totalViewers: 1 } }
    );
    const fresh = await LiveStream.findById(stream._id);
    if (fresh.viewers.length > (fresh.peakViewers || 0)) {
      fresh.peakViewers = fresh.viewers.length;
      await fresh.save();
    }

    const io = req.app.get('io');
    if (added.modifiedCount && io) {
      io.to(String(stream.host)).emit('live:viewer-joined', {
        id: String(stream._id),
        viewer: {
          ...userSummary(me),
          publicKeys: (me.publicKeys || []).map((k) => String(k).toLowerCase()),
        },
        viewerCount: fresh.viewers.length,
      });
    }

    const group = await loadGroupForStream(fresh);
    return res.json({
      success: true,
      data: {
        stream: toPublicStream(fresh, me._id, { host, group }),
        hostPublicKeys: (host.publicKeys || []).map((k) => String(k).toLowerCase()),
      },
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Could not join live stream' });
  }
}

export async function leaveLiveStream(req, res) {
  try {
    const stream = await findLiveStreamOr404(req, res);
    if (!stream) return undefined;
    await LiveStream.updateOne({ _id: stream._id }, { $pull: { viewers: { user: req.user._id } } });
    const io = req.app.get('io');
    if (io) {
      io.to(String(stream.host)).emit('live:viewer-left', {
        id: String(stream._id),
        userId: String(req.user._id),
      });
    }
    return res.json({ success: true, data: { left: true } });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Could not leave live stream' });
  }
}

/**
 * Host keep-alive (every ~10s). `connectedViewerIds` is the set of viewers
 * the host currently has a live peer connection with; anyone admitted but no
 * longer connected (closed their tab without /leave) is pruned once their
 * join grace period has passed.
 */
export async function heartbeatLiveStream(req, res) {
  try {
    const stream = await findLiveStreamOr404(req, res);
    if (!stream) return undefined;
    if (!requireHost(stream, req, res)) return undefined;
    if (stream.status !== 'live') {
      return res.status(410).json({ success: false, error: 'This live stream has ended' });
    }

    const connected = new Set(toObjectIdList(req.body?.connectedViewerIds).map(String));
    const graceCutoff = Date.now() - JOIN_GRACE_MS;
    stream.viewers = (stream.viewers || []).filter(
      (v) => connected.has(String(v.user)) || new Date(v.joinedAt).getTime() > graceCutoff
    );
    stream.lastHeartbeatAt = new Date();
    if (stream.viewers.length > (stream.peakViewers || 0)) stream.peakViewers = stream.viewers.length;
    await stream.save();

    return res.json({
      success: true,
      data: {
        viewerCount: stream.viewers.length,
        viewers: await hostViewerDetails(stream),
      },
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Heartbeat failed' });
  }
}

export async function inviteToLiveStream(req, res) {
  try {
    const stream = await findLiveStreamOr404(req, res);
    if (!stream) return undefined;
    if (!requireHost(stream, req, res)) return undefined;
    if (stream.status !== 'live') {
      return res.status(410).json({ success: false, error: 'This live stream has ended' });
    }
    const ids = toObjectIdList(req.body?.userIds).filter((id) => !id.equals(stream.host));
    if (!ids.length) {
      return res.status(400).json({ success: false, error: 'No one to invite' });
    }

    const host = await User.findById(stream.host).select(ACCESS_FIELDS);
    const invited = [];
    for (const id of ids) {
      // Same gate as a call invite: blocks and the recipient's
      // "who can message me" privacy setting both apply.
      if (!(await canUserInviteToCall(host._id, id))) continue;
      invited.push(id);
    }
    if (!invited.length) {
      return res.status(403).json({ success: false, error: 'Those contacts can’t be invited' });
    }

    const removed = new Set((stream.removed || []).map(String));
    const toInvite = invited.filter((id) => !removed.has(String(id)));
    await LiveStream.updateOne({ _id: stream._id }, { $addToSet: { invited: { $each: toInvite } } });

    const io = req.app.get('io');
    const hostName = host.displayName || host.username || 'A friend';
    const publicStream = toPublicStream(stream, null, { host });
    await Promise.all(
      toInvite.map((id) => {
        if (io) io.to(String(id)).emit('live:invited', publicStream);
        return createNotification({
          recipient: id,
          actor: host._id,
          type: 'LIVE_STARTED',
          entityType: 'live',
          entityId: String(stream._id),
          metadata: { streamId: String(stream._id), title: stream.title || '', invited: true },
          expiresAt: new Date(Date.now() + NOTIFICATION_TTL_MS),
          io,
          push: {
            title: 'QuantumChat',
            body: `${hostName} invited you to watch their live video`,
            kind: 'live',
            tag: `live:${stream._id}`,
            url: `/chat/live/${stream._id}`,
            data: { streamId: String(stream._id) },
          },
        }).catch(() => null);
      })
    );

    return res.json({ success: true, data: { invited: toInvite.map(String) } });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Could not send invites' });
  }
}

export async function removeLiveViewer(req, res) {
  try {
    const stream = await findLiveStreamOr404(req, res);
    if (!stream) return undefined;
    if (!requireHost(stream, req, res)) return undefined;
    const target = toObjectId(req.body?.userId);
    if (!target || target.equals(stream.host)) {
      return res.status(400).json({ success: false, error: 'Invalid viewer' });
    }
    await LiveStream.updateOne(
      { _id: stream._id },
      {
        $pull: { viewers: { user: target }, invited: target },
        $addToSet: { removed: target },
      }
    );
    const io = req.app.get('io');
    if (io) io.to(String(target)).emit('live:removed', { id: String(stream._id) });
    return res.json({ success: true, data: { removed: String(target) } });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Could not remove viewer' });
  }
}

export async function endLiveStream(req, res) {
  try {
    const stream = await findLiveStreamOr404(req, res);
    if (!stream) return undefined;
    if (!requireHost(stream, req, res)) return undefined;
    if (stream.status === 'live') {
      await endStream(stream, 'host', req.app.get('io'));
    }
    const host = await User.findById(stream.host).select(ACCESS_FIELDS).lean();
    const group = await loadGroupForStream(stream);
    return res.json({ success: true, data: { stream: toPublicStream(stream, req.user._id, { host, group }) } });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Could not end live stream' });
  }
}

/** Records whether the host kept or threw away their local recording. */
export async function setLiveRecordingDecision(req, res) {
  try {
    const stream = await findLiveStreamOr404(req, res);
    if (!stream) return undefined;
    if (!requireHost(stream, req, res)) return undefined;
    const decision = req.body?.decision;
    if (decision !== 'saved' && decision !== 'discarded') {
      return res.status(400).json({ success: false, error: 'decision must be "saved" or "discarded"' });
    }
    if (stream.status !== 'ended') {
      return res.status(409).json({ success: false, error: 'End the live stream first' });
    }
    if (!stream.recording?.enabled) {
      return res.status(409).json({ success: false, error: 'This live stream was not recorded' });
    }
    stream.recording.decision = decision;
    await stream.save();
    return res.json({ success: true, data: { recording: { enabled: true, decision } } });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Could not update recording' });
  }
}
