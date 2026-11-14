import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { createGroup, registerUser, startTestServer } from '../helpers/testServer.js';
import { authHeaders } from '../helpers/attacks.js';
import { sealMessage } from '../helpers/crypto.js';

let ctx;
let User;
let LiveStream;
let host;
let friend;
let hiddenFriend;
let stranger;
let blocker;
let mutedFriend;

async function api(method, path, token, body) {
  const res = await fetch(`${ctx.base}${path}`, {
    method,
    headers: authHeaders(token),
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: res.status, body: await res.json().catch(() => ({})) };
}

async function makeFriends(a, b) {
  await User.updateOne({ _id: a.user.id }, { $addToSet: { friends: b.user.id } });
  await User.updateOne({ _id: b.user.id }, { $addToSet: { friends: a.user.id } });
}

async function goLive(token, body = {}) {
  const res = await api('POST', '/live', token, body);
  assert.equal(res.status, 201, JSON.stringify(res.body));
  return res.body.data.stream;
}

function liveSignal(from, to, streamId, event = 'live:offer') {
  return api('POST', '/call-signals', from.token, {
    to: to.user.id,
    callId: streamId,
    event,
    envelope: sealMessage(JSON.stringify({ type: 'offer', sdp: { type: 'offer', sdp: 'v=0' } }), to.keySet[0].publicKey),
  });
}

async function waitFor(fn, timeoutMs = 3000) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const value = await fn();
    if (value || Date.now() > deadline) return value;
    await new Promise((r) => setTimeout(r, 50));
  }
}

before(async () => {
  ctx = await startTestServer();
  User = (await import('../../src/models/User.js')).default;
  LiveStream = (await import('../../src/models/LiveStream.js')).default;
  const s = `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 5)}`;
  host = await registerUser(ctx.base, `lv_host_${s}`);
  friend = await registerUser(ctx.base, `lv_friend_${s}`);
  hiddenFriend = await registerUser(ctx.base, `lv_hidden_${s}`);
  stranger = await registerUser(ctx.base, `lv_stranger_${s}`);
  blocker = await registerUser(ctx.base, `lv_blocker_${s}`);
  mutedFriend = await registerUser(ctx.base, `lv_muted_${s}`);
  for (const u of [friend, hiddenFriend, blocker, mutedFriend]) await makeFriends(host, u);
  await api('POST', `/users/${host.user.id}/block`, blocker.token);
  await api('PUT', '/users/me/notification-settings', mutedFriend.token, { liveNotifications: false });
});

after(async () => {
  await ctx.stop();
});

test('friends-audience stream is visible and joinable only by non-hidden, non-blocking friends', async () => {
  const stream = await goLive(host.token, {
    title: 'Hello\u0000 world',
    audience: { type: 'friends', hiddenFrom: [hiddenFriend.user.id] },
  });
  assert.equal(stream.title, 'Hello  world');
  assert.equal(stream.isHost, true);

  const friendList = await api('GET', '/live', friend.token);
  assert.ok(friendList.body.data.streams.some((st) => st.id === stream.id));
  for (const outsider of [hiddenFriend, stranger, blocker]) {
    const list = await api('GET', '/live', outsider.token);
    assert.equal(list.body.data.streams.some((st) => st.id === stream.id), false);
    const join = await api('POST', `/live/${stream.id}/join`, outsider.token);
    assert.equal(join.status, 403);
  }

  const join = await api('POST', `/live/${stream.id}/join`, friend.token);
  assert.equal(join.status, 200);
  assert.equal(join.body.data.stream.viewerCount, 1);
  assert.deepEqual(join.body.data.hostPublicKeys, host.keySet.map((k) => k.publicKey.toLowerCase()));
  // Viewers never see the host-only audience details.
  assert.equal(join.body.data.stream.audience, undefined);

  await api('POST', `/live/${stream.id}/end`, host.token);
});

test('go-live notifies the audience but respects the liveNotifications opt-out', async () => {
  const stream = await goLive(host.token, { audience: { type: 'friends' } });
  const notified = await waitFor(async () => {
    const res = await api('GET', '/notifications', friend.token);
    return res.body.data.find((n) => n.type === 'LIVE_STARTED' && n.entityId === stream.id);
  });
  assert.ok(notified, 'friend should get a LIVE_STARTED notification');

  const muted = await api('GET', '/notifications', mutedFriend.token);
  assert.equal(muted.body.data.some((n) => n.type === 'LIVE_STARTED'), false);
  const blocked = await api('GET', '/notifications', blocker.token);
  assert.equal(blocked.body.data.some((n) => n.type === 'LIVE_STARTED'), false);

  await api('POST', `/live/${stream.id}/end`, host.token);
});

test('group and custom audiences are enforced', async () => {
  const group = await createGroup(ctx.base, host.token, { name: 'Live group', memberIds: [stranger.user.id] });
  const groupStream = await goLive(host.token, { audience: { type: 'group', groupId: group.id } });
  assert.equal((await api('POST', `/live/${groupStream.id}/join`, stranger.token)).status, 200);
  assert.equal((await api('POST', `/live/${groupStream.id}/join`, friend.token)).status, 403);

  // Can't go live to a group you aren't in.
  const otherGroup = await createGroup(ctx.base, stranger.token, { name: 'Not hosts', memberIds: [] });
  const denied = await api('POST', '/live', host.token, { audience: { type: 'group', groupId: otherGroup.id } });
  assert.equal(denied.status, 403);

  // Custom audiences only keep the host's friends.
  const custom = await goLive(host.token, { audience: { type: 'custom', userIds: [friend.user.id, stranger.user.id] } });
  assert.equal((await api('POST', `/live/${custom.id}/join`, friend.token)).status, 200);
  assert.equal((await api('POST', `/live/${custom.id}/join`, stranger.token)).status, 403);
  assert.equal((await api('POST', `/live/${custom.id}/join`, hiddenFriend.token)).status, 403);

  // Starting a new stream replaced the group one.
  const replaced = await api('POST', `/live/${groupStream.id}/join`, stranger.token);
  assert.equal(replaced.status, 410);
  await api('POST', `/live/${custom.id}/end`, host.token);
});

test('live signaling is relayed only between the host and admitted viewers', async () => {
  const stream = await goLive(host.token, { audience: { type: 'friends' } });
  assert.equal((await liveSignal(friend, host, stream.id)).status, 403, 'not joined yet');
  await api('POST', `/live/${stream.id}/join`, friend.token);
  assert.equal((await liveSignal(friend, host, stream.id)).status, 201);
  assert.equal((await liveSignal(host, friend, stream.id, 'live:answer')).status, 201);
  assert.equal((await liveSignal(stranger, host, stream.id)).status, 403);
  // Viewer-to-viewer is not a host pair.
  await api('POST', `/live/${stream.id}/join`, hiddenFriend.token);
  assert.equal((await liveSignal(friend, hiddenFriend, stream.id)).status, 403);

  const plaintext = await api('POST', '/call-signals', friend.token, {
    to: host.user.id,
    callId: stream.id,
    event: 'live:offer',
    envelope: { sdp: 'v=0' },
  });
  assert.equal(plaintext.status, 400);
  await api('POST', `/live/${stream.id}/end`, host.token);
});

test('host can invite contacts and remove viewers; only the host controls the stream', async () => {
  const stream = await goLive(host.token, { audience: { type: 'custom', userIds: [friend.user.id] } });
  assert.equal((await api('POST', `/live/${stream.id}/join`, stranger.token)).status, 403);
  const invite = await api('POST', `/live/${stream.id}/invite`, host.token, { userIds: [stranger.user.id] });
  assert.equal(invite.status, 200);
  assert.deepEqual(invite.body.data.invited, [stranger.user.id]);
  assert.equal((await api('POST', `/live/${stream.id}/join`, stranger.token)).status, 200);

  const removed = await api('POST', `/live/${stream.id}/remove`, host.token, { userId: stranger.user.id });
  assert.equal(removed.status, 200);
  assert.equal((await api('POST', `/live/${stream.id}/join`, stranger.token)).status, 403);
  assert.equal((await liveSignal(stranger, host, stream.id)).status, 403);

  for (const [path, body] of [
    ['heartbeat', {}],
    ['invite', { userIds: [stranger.user.id] }],
    ['remove', { userId: friend.user.id }],
    ['end', {}],
  ]) {
    assert.equal((await api('POST', `/live/${stream.id}/${path}`, friend.token, body)).status, 403, path);
  }
  await api('POST', `/live/${stream.id}/end`, host.token);
});

test('heartbeat prunes disconnected viewers and stale streams expire', async () => {
  const stream = await goLive(host.token, { audience: { type: 'friends' } });
  await api('POST', `/live/${stream.id}/join`, friend.token);
  await LiveStream.updateOne(
    { _id: stream.id },
    { $set: { 'viewers.0.joinedAt': new Date(Date.now() - 60_000) } }
  );
  const beat = await api('POST', `/live/${stream.id}/heartbeat`, host.token, { connectedViewerIds: [] });
  assert.equal(beat.status, 200);
  assert.equal(beat.body.data.viewerCount, 0);

  await LiveStream.updateOne({ _id: stream.id }, { $set: { lastHeartbeatAt: new Date(Date.now() - 120_000) } });
  const list = await api('GET', '/live', friend.token);
  assert.equal(list.body.data.streams.some((st) => st.id === stream.id), false);
  assert.equal((await api('POST', `/live/${stream.id}/join`, friend.token)).status, 410);
});

test('recording decision is host-only metadata recorded after the stream ends', async () => {
  const recorded = await goLive(host.token, { audience: { type: 'friends' }, record: true });
  assert.equal((await api('POST', `/live/${recorded.id}/recording`, host.token, { decision: 'saved' })).status, 409);
  const ended = await api('POST', `/live/${recorded.id}/end`, host.token);
  assert.equal(ended.body.data.stream.recording.decision, 'pending');
  assert.equal((await api('POST', `/live/${recorded.id}/recording`, friend.token, { decision: 'saved' })).status, 403);
  assert.equal((await api('POST', `/live/${recorded.id}/recording`, host.token, { decision: 'bogus' })).status, 400);
  const saved = await api('POST', `/live/${recorded.id}/recording`, host.token, { decision: 'discarded' });
  assert.equal(saved.body.data.recording.decision, 'discarded');

  const unrecorded = await goLive(host.token, { audience: { type: 'friends' } });
  await api('POST', `/live/${unrecorded.id}/end`, host.token);
  assert.equal((await api('POST', `/live/${unrecorded.id}/recording`, host.token, { decision: 'saved' })).status, 409);
});
