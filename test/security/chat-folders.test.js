import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { registerUser, startTestServer } from '../helpers/testServer.js';
import { authHeaders } from '../helpers/attacks.js';

let ctx;
let alice;
let bob;

async function api(method, path, token, body) {
  const res = await fetch(`${ctx.base}${path}`, {
    method,
    headers: authHeaders(token),
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: res.status, body: await res.json().catch(() => ({})) };
}

before(async () => {
  ctx = await startTestServer();
  const s = `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 5)}`;
  alice = await registerUser(ctx.base, `cf_alice_${s}`);
  bob = await registerUser(ctx.base, `cf_bob_${s}`);
});

after(async () => {
  await ctx.stop();
});

test('create, add a chat, rename and delete a folder', async () => {
  const created = await api('POST', '/users/me/chat-folders', alice.token, { name: '  Work  ' });
  assert.equal(created.status, 201, JSON.stringify(created.body));
  const folderId = created.body.folderId;
  assert.deepEqual(created.body.data, [{ id: folderId, name: 'Work', conversationKeys: [] }]);

  const key = `dm:${bob.user.id}`;
  const added = await api('PUT', `/users/me/chat-folders/${folderId}/chats`, alice.token, {
    conversationKey: key,
    included: true,
  });
  assert.equal(added.status, 200);
  assert.deepEqual(added.body.data[0].conversationKeys, [key]);

  const again = await api('PUT', `/users/me/chat-folders/${folderId}/chats`, alice.token, {
    conversationKey: key,
    included: true,
  });
  assert.deepEqual(again.body.data[0].conversationKeys, [key], 'adding twice does not duplicate');

  const renamed = await api('PATCH', `/users/me/chat-folders/${folderId}`, alice.token, { name: 'Office' });
  assert.equal(renamed.body.data[0].name, 'Office');

  const me = await api('GET', '/users/me', alice.token);
  assert.equal(me.body.data.chatFolders[0].name, 'Office', 'folders are returned on the self profile');

  const removed = await api('PUT', `/users/me/chat-folders/${folderId}/chats`, alice.token, {
    conversationKey: key,
    included: false,
  });
  assert.deepEqual(removed.body.data[0].conversationKeys, []);

  const deleted = await api('DELETE', `/users/me/chat-folders/${folderId}`, alice.token);
  assert.equal(deleted.status, 200);
  assert.deepEqual(deleted.body.data, []);
});

test('rejects bad names, duplicates and malformed conversation keys', async () => {
  assert.equal((await api('POST', '/users/me/chat-folders', alice.token, { name: '   ' })).status, 400);
  assert.equal((await api('POST', '/users/me/chat-folders', alice.token, { name: 'x'.repeat(25) })).status, 400);

  const family = await api('POST', '/users/me/chat-folders', alice.token, { name: 'Family' });
  assert.equal(family.status, 201);
  assert.equal((await api('POST', '/users/me/chat-folders', alice.token, { name: 'family' })).status, 409);

  const bad = await api('PUT', `/users/me/chat-folders/${family.body.folderId}/chats`, alice.token, {
    conversationKey: { $gt: '' },
  });
  assert.equal(bad.status, 400);
  const badList = await api('PATCH', `/users/me/chat-folders/${family.body.folderId}`, alice.token, {
    conversationKeys: ['dm:not-an-id'],
  });
  assert.equal(badList.status, 400);

  await api('DELETE', `/users/me/chat-folders/${family.body.folderId}`, alice.token);
});

test('folders are private to their owner', async () => {
  const mine = await api('POST', '/users/me/chat-folders', alice.token, { name: 'Private' });
  const folderId = mine.body.folderId;

  assert.equal((await api('PATCH', `/users/me/chat-folders/${folderId}`, bob.token, { name: 'Hijack' })).status, 404);
  assert.equal((await api('DELETE', `/users/me/chat-folders/${folderId}`, bob.token)).status, 404);

  const bobView = await api('GET', `/users/${alice.user.id}`, bob.token);
  assert.equal(bobView.body.data?.chatFolders, undefined, 'never on the public profile');

  await api('DELETE', `/users/me/chat-folders/${folderId}`, alice.token);
});

test('caps the number of folders', async () => {
  const ids = [];
  for (let i = 0; i < 10; i += 1) {
    const r = await api('POST', '/users/me/chat-folders', alice.token, { name: `F${i}` });
    assert.equal(r.status, 201);
    ids.push(r.body.folderId);
  }
  assert.equal((await api('POST', '/users/me/chat-folders', alice.token, { name: 'One more' })).status, 400);
  for (const id of ids) await api('DELETE', `/users/me/chat-folders/${id}`, alice.token);
});

test('accounts with the legacy statusNotifications value can still save folders', async () => {
  // Older builds stored 'favorites_only' (since renamed 'selected'). Write it
  // straight to the collection, bypassing validation, like a real old account.
  const { default: User } = await import('../../src/models/User.js');
  await User.collection.updateOne(
    { _id: new User.base.Types.ObjectId(bob.user.id) },
    { $set: { 'notificationSettings.statusNotifications': 'favorites_only' } }
  );

  const created = await api('POST', '/users/me/chat-folders', bob.token, { name: 'Legacy' });
  assert.equal(created.status, 201, JSON.stringify(created.body));
  const added = await api('PUT', `/users/me/chat-folders/${created.body.folderId}/chats`, bob.token, {
    conversationKey: `dm:${alice.user.id}`,
    included: true,
  });
  assert.equal(added.status, 200, JSON.stringify(added.body));

  const stored = await User.collection.findOne({ _id: new User.base.Types.ObjectId(bob.user.id) });
  assert.equal(stored.notificationSettings.statusNotifications, 'selected');
  const settings = await api('GET', '/users/me/notification-settings', bob.token);
  assert.equal(settings.body.data.statusNotifications, 'selected');
});
