import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { startTestServer, registerUser } from '../helpers/testServer.js';
import { authHeaders } from '../helpers/attacks.js';
import { sealMessage, unsealMessage } from '../helpers/crypto.js';

let ctx;
let alice;
let bob;

before(async () => {
  ctx = await startTestServer();
  const suffix = `${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
  alice = await registerUser(ctx.base, `call_alice_${suffix}`);
  bob = await registerUser(ctx.base, `call_bob_${suffix}`);
});

after(async () => {
  await ctx.stop();
});

test('REST call signaling relays only an X5 sealed envelope to its recipient', async () => {
  const callId = crypto.randomUUID();
  const plaintext = JSON.stringify({ type: 'invite', callId, video: true });
  const envelope = sealMessage(plaintext, bob.keySet[0].publicKey);

  const created = await fetch(`${ctx.base}/call-signals`, {
    method: 'POST',
    headers: authHeaders(alice.token),
    body: JSON.stringify({
      to: bob.user.id,
      callId,
      event: 'call:invite',
      envelope,
    }),
  });
  assert.equal(created.status, 201);

  const inbox = await fetch(
    `${ctx.base}/call-signals?after=${encodeURIComponent(new Date(Date.now() - 10_000).toISOString())}`,
    { headers: authHeaders(bob.token) }
  ).then((res) => res.json());

  assert.equal(inbox.success, true);
  const signal = inbox.data.signals.find((item) => item.callId === callId);
  assert.ok(signal);
  assert.equal(signal.event, 'call:invite');
  assert.equal(String(signal.from), String(alice.user.id));
  assert.equal(unsealMessage(signal.envelope, bob.keySet[0].secretKey), plaintext);
  assert.equal(JSON.stringify(signal).includes(plaintext), false);

  const aliceInbox = await fetch(
    `${ctx.base}/call-signals?after=${encodeURIComponent(new Date(Date.now() - 10_000).toISOString())}`,
    { headers: authHeaders(alice.token) }
  ).then((res) => res.json());
  assert.equal(aliceInbox.data.signals.some((item) => item.callId === callId), false);
});

test('REST call signaling rejects plaintext SDP and candidates', async () => {
  const response = await fetch(`${ctx.base}/call-signals`, {
    method: 'POST',
    headers: authHeaders(alice.token),
    body: JSON.stringify({
      to: bob.user.id,
      callId: crypto.randomUUID(),
      event: 'call:offer',
      sdp: { type: 'offer', sdp: 'v=0' },
    }),
  });
  assert.equal(response.status, 400);
});
