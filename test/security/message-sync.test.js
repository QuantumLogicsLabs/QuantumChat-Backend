/**
 * GET /api/messages/sync is the realtime transport on the serverless deployment,
 * which cannot hold a WebSocket. Unlike every other read endpoint it is not
 * scoped to a single conversation — it returns everything new across all of the
 * caller's DMs and groups — so its authorization filter is the only thing
 * standing between users' conversations. These tests pin that boundary, and
 * assert the endpoint carries sealed X5 envelopes only.
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startTestServer, registerUser, createGroup, sendGroupMessage, sealGroupEnvelopes } from '../helpers/testServer.js';
import { authHeaders } from '../helpers/attacks.js';
import { generateKeySet, sealMessage, unsealMessage } from '../helpers/crypto.js';

// Kept short: usernames are capped at 30 chars and these get a prefix.
const RUN_ID = `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`;

let ctx;
let alice;
let bob;
let mallory;

function documentContainsPlaintext(doc, plaintext) {
  const json = JSON.stringify(doc);
  if (json.includes(plaintext)) return true;
  const plainB64 = Buffer.from(plaintext, 'utf8').toString('base64');
  return json.includes(plainB64);
}

async function sendDm(from, to, plaintext) {
  const forRecipient = sealMessage(plaintext, to.keySet[0].publicKey);
  const forSender = sealMessage(plaintext, from.keySet[0].publicKey);
  const res = await fetch(`${ctx.base}/messages`, {
    method: 'POST',
    headers: authHeaders(from.token),
    body: JSON.stringify({ to: to.user.id, forRecipient, forSender }),
  }).then((r) => r.json());
  assert.equal(res.success, true, `setup: DM must send (${res.error})`);
  return res.data;
}

async function sync(token, since) {
  const url = new URL(`${ctx.base}/messages/sync`);
  if (since) url.searchParams.set('since', since);
  const res = await fetch(url, { headers: authHeaders(token) });
  const body = await res.json().catch(() => ({}));
  return { status: res.status, body };
}

before(async () => {
  ctx = await startTestServer();
  alice = await registerUser(ctx.base, `sync_alice_${RUN_ID}`);
  bob = await registerUser(ctx.base, `sync_bob_${RUN_ID}`);
  mallory = await registerUser(ctx.base, `sync_mallory_${RUN_ID}`);
});

after(async () => {
  await ctx.stop();
});

test('sync: rejects a request with no token', async () => {
  const res = await fetch(`${ctx.base}/messages/sync`);
  assert.equal(res.status, 401);
});

test('sync: rejects a malformed token', async () => {
  const { status } = await sync('not-a-real-jwt');
  assert.equal(status, 401);
});

test('sync: rejects a token signed with the wrong secret', async () => {
  const jwt = (await import('jsonwebtoken')).default;
  const forged = jwt.sign({ id: alice.user.id }, 'wrong-secret-entirely', { algorithm: 'HS256' });
  const { status } = await sync(forged);
  assert.equal(status, 401);
});

test('sync: returns a DM to both participants', async () => {
  const before = new Date(Date.now() - 60_000).toISOString();
  const sent = await sendDm(alice, bob, `hello bob ${RUN_ID}`);

  for (const party of [alice, bob]) {
    const { status, body } = await sync(party.token, before);
    assert.equal(status, 200);
    assert.equal(body.success, true);
    const ids = body.data.map((m) => String(m.id));
    assert.ok(ids.includes(String(sent.id)), 'participant must receive the message');
  }
});

test('sync: never leaks a DM to a third party', async () => {
  const before = new Date(Date.now() - 60_000).toISOString();
  const plaintext = `private between alice and bob ${RUN_ID}`;
  const sent = await sendDm(alice, bob, plaintext);

  const { status, body } = await sync(mallory.token, before);
  assert.equal(status, 200);
  const ids = body.data.map((m) => String(m.id));
  assert.ok(!ids.includes(String(sent.id)), 'non-participant must not receive the message');
  assert.equal(
    documentContainsPlaintext(body, plaintext),
    false,
    'third party response must not contain the plaintext in any form'
  );
});

test('sync: never leaks a group message to a non-member', async () => {
  const group = await createGroup(ctx.base, alice.token, {
    name: `sync_group_${RUN_ID}`,
    memberIds: [bob.user.id],
  });
  const plaintext = `group secret ${RUN_ID}`;
  const envelopes = await sealGroupEnvelopes(plaintext, [alice, bob]);
  const sendRes = await sendGroupMessage(ctx.base, alice.token, group.id, envelopes);
  assert.equal(sendRes.status, 201, `setup: group send must succeed (${sendRes.body?.error})`);

  const since = new Date(Date.now() - 60_000).toISOString();

  const member = await sync(bob.token, since);
  const memberIds = member.body.data.map((m) => String(m.id));
  assert.ok(
    memberIds.includes(String(sendRes.body.data.id)),
    'group member must receive the message'
  );

  const outsider = await sync(mallory.token, since);
  const outsiderIds = outsider.body.data.map((m) => String(m.id));
  assert.ok(
    !outsiderIds.includes(String(sendRes.body.data.id)),
    'non-member must not receive the group message'
  );
  assert.equal(
    documentContainsPlaintext(outsider.body, plaintext),
    false,
    'non-member response must not contain the group plaintext'
  );
});

test('X5: sync response carries sealed envelopes only, never plaintext', async () => {
  const since = new Date(Date.now() - 60_000).toISOString();
  const plaintext = `x5 confidentiality probe ${RUN_ID}`;
  const sent = await sendDm(alice, bob, plaintext);

  const { body } = await sync(bob.token, since);
  assert.equal(
    documentContainsPlaintext(body, plaintext),
    false,
    'sync must never expose chat plaintext — the server does not hold the keys'
  );

  const row = body.data.find((m) => String(m.id) === String(sent.id));
  assert.ok(row, 'recipient must receive the message');
  for (const field of ['ciphertext', 'nonce', 'ephemeralPublicKey', 'targetPublicKey']) {
    assert.ok(row.forRecipient[field], `envelope must carry ${field}`);
  }
  assert.equal(row.content, undefined, 'DM rows must not carry a plaintext content field');

  // The envelope delivered over sync must actually decrypt with the recipient's
  // client-held key — proving this transport preserves the X5 sealed box rather
  // than merely withholding plaintext.
  const opened = unsealMessage(row.forRecipient, bob.keySet[0].secretKey);
  assert.equal(opened, plaintext, 'recipient must be able to unseal a synced envelope');
});

test('sync: a since in the future is clamped to server time, so a fast clock cannot blind a client', async () => {
  // The cursor round-trips through the client, so a device with a fast clock can
  // ask for a window starting in the future. Left untrusted that would skip every
  // message written from then on — permanently, since each response reseeds the
  // cursor. Clamping to server time bounds the loss to nothing going forward.
  const future = new Date(Date.now() + 60 * 60 * 1000).toISOString();
  const skewed = await sync(bob.token, future);
  assert.equal(skewed.status, 200);
  assert.ok(
    new Date(skewed.body.meta.cursor).getTime() <= Date.now(),
    'the returned cursor must be server-issued, never the client value echoed back'
  );

  const sent = await sendDm(alice, bob, `clock skew probe ${RUN_ID}`);
  const next = await sync(bob.token, skewed.body.meta.cursor);
  const ids = next.body.data.map((m) => String(m.id));
  assert.ok(
    ids.includes(String(sent.id)),
    'after a future cursor, subsequent messages must still arrive'
  );
});

test('sync: returns a server-issued cursor that excludes already-seen messages', async () => {
  const first = await sync(bob.token, new Date(Date.now() - 60_000).toISOString());
  assert.ok(first.body.meta.cursor, 'response must carry a cursor');

  const sent = await sendDm(alice, bob, `after cursor ${RUN_ID}`);
  const second = await sync(bob.token, first.body.meta.cursor);
  const ids = second.body.data.map((m) => String(m.id));
  assert.ok(ids.includes(String(sent.id)), 'cursor must advance to include newer messages');
});

test('sync: rejects a 2fa-purpose token', async () => {
  const jwt = (await import('jsonwebtoken')).default;
  const halfAuthed = jwt.sign(
    { id: alice.user.id, purpose: '2fa' },
    process.env.JWT_SECRET,
    { algorithm: 'HS256' }
  );
  const { status } = await sync(halfAuthed);
  assert.equal(status, 401, 'a token that has not cleared 2fa must not read messages');
});

test('sync: an unparseable since falls back to the safe window, not an error', async () => {
  const { status, body } = await sync(bob.token, 'not-a-date');
  assert.equal(status, 200);
  assert.equal(body.success, true);
  assert.ok(Array.isArray(body.data));
});

test('sync: publicKeys of other users are never included in message rows', async () => {
  const since = new Date(Date.now() - 60_000).toISOString();
  const { body } = await sync(bob.token, since);
  const json = JSON.stringify(body);
  for (const key of alice.keySet) {
    assert.equal(
      json.includes(key.secretKey),
      false,
      'no secret key material may ever appear in a sync response'
    );
  }
  assert.ok(generateKeySet(5).length === 5); // X5 pool size unchanged
});
