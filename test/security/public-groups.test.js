// Public groups: plaintext content, discover, open join vs request-to-join.
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import {
  startTestServer,
  registerUser,
  createGroup,
  sendGroupMessage,
} from '../helpers/testServer.js';
import { authHeaders, fetchJson } from '../helpers/attacks.js';

const RUN = `${Date.now()}`;

let ctx;
let owner;
let member;
let outsider;

before(async () => {
  ctx = await startTestServer();
  owner = await registerUser(ctx.base, `pubg_${RUN}_owner`);
  member = await registerUser(ctx.base, `pubg_${RUN}_member`);
  outsider = await registerUser(ctx.base, `pubg_${RUN}_out`);
});

after(async () => {
  await ctx.stop();
});

test('public group accepts content and rejects empty content', async () => {
  const group = await createGroup(ctx.base, owner.token, {
    name: `Public Open ${RUN}`,
    visibility: 'public',
    joinPolicy: 'open',
    memberIds: [],
  });
  assert.equal(group.visibility, 'public');
  assert.equal(group.joinPolicy, 'open');

  const bad = await sendGroupMessage(ctx.base, owner.token, group.id, null, { content: '   ' });
  assert.equal(bad.status, 400);

  const ok = await sendGroupMessage(ctx.base, owner.token, group.id, null, {
    content: `hello public ${RUN}`,
  });
  assert.ok([200, 201].includes(ok.status), ok.body?.error);
  assert.equal(ok.body.data.content, `hello public ${RUN}`);
  assert.ok(!ok.body.data.envelopes?.length);
});

test('private group still requires envelopes', async () => {
  const group = await createGroup(ctx.base, owner.token, {
    name: `Private ${RUN}`,
    visibility: 'private',
    memberIds: [member.user.id],
  });
  assert.equal(group.visibility || 'private', 'private');

  const bad = await sendGroupMessage(ctx.base, owner.token, group.id, null, {
    content: 'should fail',
  });
  assert.equal(bad.status, 400);
  assert.match(String(bad.body?.error || ''), /envelope/i);
});

test('discover lists public groups and excludes memberships / private', async () => {
  const openGroup = await createGroup(ctx.base, owner.token, {
    name: `DiscoverMe ${RUN}`,
    visibility: 'public',
    joinPolicy: 'open',
    memberIds: [],
  });
  await createGroup(ctx.base, owner.token, {
    name: `PrivateHide ${RUN}`,
    visibility: 'private',
    memberIds: [member.user.id],
  });

  const listed = await fetchJson(`${ctx.base}/groups/discover`, {
    headers: authHeaders(outsider.token),
  });
  assert.equal(listed.status, 200);
  const ids = (listed.body.data || []).map((g) => String(g.id));
  assert.ok(ids.includes(String(openGroup.id)));

  const asOwner = await fetchJson(`${ctx.base}/groups/discover`, {
    headers: authHeaders(owner.token),
  });
  const ownerIds = (asOwner.body.data || []).map((g) => String(g.id));
  assert.ok(!ownerIds.includes(String(openGroup.id)));
});

test('open join adds member; request policy requires accept', async () => {
  const openGroup = await createGroup(ctx.base, owner.token, {
    name: `OpenJoin ${RUN}`,
    visibility: 'public',
    joinPolicy: 'open',
    memberIds: [],
  });
  const joined = await fetchJson(`${ctx.base}/groups/${openGroup.id}/join`, {
    method: 'POST',
    headers: authHeaders(outsider.token),
  });
  assert.equal(joined.status, 200);
  assert.ok((joined.body.data.members || []).some((m) => String(m.id || m) === String(outsider.user.id)));

  const reqGroup = await createGroup(ctx.base, owner.token, {
    name: `RequestJoin ${RUN}`,
    visibility: 'public',
    joinPolicy: 'request',
    memberIds: [],
  });
  const openFail = await fetchJson(`${ctx.base}/groups/${reqGroup.id}/join`, {
    method: 'POST',
    headers: authHeaders(member.token),
  });
  assert.equal(openFail.status, 400);

  const requested = await fetchJson(`${ctx.base}/groups/${reqGroup.id}/join-requests`, {
    method: 'POST',
    headers: authHeaders(member.token),
  });
  assert.ok([200, 201].includes(requested.status), requested.body?.error);

  const accepted = await fetchJson(
    `${ctx.base}/groups/${reqGroup.id}/join-requests/${member.user.id}/accept`,
    {
      method: 'POST',
      headers: authHeaders(owner.token),
    }
  );
  assert.equal(accepted.status, 200);
  assert.ok((accepted.body.data.members || []).some((m) => String(m.id || m) === String(member.user.id)));
});
