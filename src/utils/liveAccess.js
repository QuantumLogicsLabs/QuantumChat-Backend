import Group from '../models/Group.js';
import LiveStream, { LIVE_HEARTBEAT_STALE_MS } from '../models/LiveStream.js';
import User from '../models/User.js';
import { toObjectId } from './toObjectId.js';

const MAX_NOTIFIED_AUDIENCE = 500;

function idSet(list) {
  return new Set((list || []).map((v) => String(v?._id || v)));
}

function isBlockedEitherWay(host, viewer) {
  const hostId = String(host._id);
  const viewerId = String(viewer._id);
  return idSet(host.blockedUsers).has(viewerId) || idSet(viewer.blockedUsers).has(hostId);
}

/**
 * Lazily ends streams whose host stopped heartbeating (closed the tab, lost
 * network). Serverless deployments have no long-lived process to run a sweep
 * on a timer, so every read path calls this first instead.
 */
export async function expireStaleLiveStreams() {
  const cutoff = new Date(Date.now() - LIVE_HEARTBEAT_STALE_MS);
  const stale = await LiveStream.find({ status: 'live', lastHeartbeatAt: { $lt: cutoff } }).limit(50);
  await Promise.all(
    stale.map((stream) => {
      stream.markEnded('timeout');
      return stream.save().catch(() => {});
    })
  );
  return stale;
}

/**
 * Whether `viewer` may watch `stream`. `host` and `viewer` must carry
 * `friends` and `blockedUsers`. Blocking (either direction) and removal
 * always win; an explicit invite admits anyone else the host invited.
 */
export async function canViewLiveStream(stream, host, viewer) {
  if (!stream || !host || !viewer) return false;
  const viewerId = String(viewer._id);
  if (String(host._id) === viewerId) return true;
  if (stream.status !== 'live') return false;
  if (isBlockedEitherWay(host, viewer)) return false;
  if (idSet(stream.removed).has(viewerId)) return false;
  if (idSet(stream.invited).has(viewerId)) return true;

  const audience = stream.audience || {};
  if (idSet(audience.hiddenFrom).has(viewerId)) return false;

  if (audience.type === 'custom') {
    return idSet(audience.users).has(viewerId);
  }
  if (audience.type === 'group') {
    if (!audience.group) return false;
    return Boolean(await Group.exists({ _id: audience.group, members: viewer._id }));
  }
  // 'friends'
  return idSet(host.friends).has(viewerId);
}

/** User ids the stream's audience resolves to (for go-live notifications). */
export async function resolveLiveAudienceIds(stream, host) {
  const audience = stream.audience || {};
  let ids = [];
  if (audience.type === 'custom') {
    ids = [...idSet(audience.users)];
  } else if (audience.type === 'group' && audience.group) {
    const group = await Group.findById(audience.group).select('members').lean();
    ids = [...idSet(group?.members)];
  } else {
    ids = [...idSet(host.friends)];
  }

  const hostId = String(host._id);
  const hidden = idSet(audience.hiddenFrom);
  const removed = idSet(stream.removed);
  const hostBlocked = idSet(host.blockedUsers);
  ids = ids.filter((id) => id !== hostId && !hidden.has(id) && !removed.has(id) && !hostBlocked.has(id));
  if (!ids.length) return [];

  // Drop anyone who blocked the host.
  const candidates = await User.find({ _id: { $in: ids.slice(0, MAX_NOTIFIED_AUDIENCE) } })
    .select('_id blockedUsers')
    .lean();
  return candidates
    .filter((u) => !idSet(u.blockedUsers).has(hostId))
    .map((u) => String(u._id));
}

/**
 * Live signaling (offer/answer/ice/leave/end) is only relayed between a live
 * stream's host and a viewer the server already admitted via /live/:id/join.
 * Without this, anyone could aim WebRTC offers at a host just by knowing a
 * stream id.
 */
export async function canRelayLiveSignal(fromId, toId, streamId) {
  const sid = toObjectId(streamId);
  const from = toObjectId(fromId);
  const to = toObjectId(toId);
  if (!sid || !from || !to) return false;
  return Boolean(
    await LiveStream.exists({
      _id: sid,
      status: 'live',
      $or: [
        { host: from, 'viewers.user': to },
        { host: to, 'viewers.user': from },
      ],
    })
  );
}
