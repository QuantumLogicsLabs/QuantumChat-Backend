import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import mongoose from 'mongoose';
import Attachment from '../../src/models/Attachment.js';
import { startTestServer, registerUser } from '../helpers/testServer.js';
import { authHeaders } from '../helpers/attacks.js';
import { sealBytes, sealMessage, unsealMessage } from '../helpers/crypto.js';
import { toClientMessage } from '../../src/controllers/messageController.js';

const RUN_ID = `${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
let context;
let alice;
let bob;
let mallory;
let messageId;
let attachmentId;

before(async () => {
  context = await startTestServer();
  [alice, bob, mallory] = await Promise.all([
    registerUser(context.base, `ta_${RUN_ID}`),
    registerUser(context.base, `tb_${RUN_ID}`),
    registerUser(context.base, `tm_${RUN_ID}`),
  ]);

  const recipientAudio = sealBytes(Buffer.from('voice'), bob.keySet[0].publicKey);
  const senderAudio = sealBytes(Buffer.from('voice'), alice.keySet[0].publicKey);
  const attachment = await Attachment.create({
    owner: alice.user.id,
    recipient: bob.user.id,
    filename: 'voice-note.webm',
    mimetype: 'audio/webm',
    size: 5,
    storagePath: `test/${RUN_ID}/voice.enc`,
    storageProvider: 'memory',
    nonce: recipientAudio.nonce,
    ephemeralPublicKey: recipientAudio.ephemeralPublicKey,
    targetPublicKey: recipientAudio.targetPublicKey,
    forSenderStoragePath: `test/${RUN_ID}/voice-sender.enc`,
    forSenderNonce: senderAudio.nonce,
    forSenderEphemeralPublicKey: senderAudio.ephemeralPublicKey,
    forSenderTargetPublicKey: senderAudio.targetPublicKey,
  });
  attachmentId = String(attachment._id);

  const messageResponse = await fetch(`${context.base}/messages`, {
    method: 'POST',
    headers: authHeaders(alice.token),
    body: JSON.stringify({
      to: bob.user.id,
      forRecipient: sealMessage('sealed body', bob.keySet[0].publicKey),
      forSender: sealMessage('sealed body', alice.keySet[0].publicKey),
      attachmentId,
    }),
  });
  const body = await messageResponse.json();
  assert.equal(body.success, true, `setup message failed: ${body.error}`);
  messageId = String(body.data.id || body.data._id);
});

after(async () => {
  try {
    if (messageId) await mongoose.connection.db.collection('messages').deleteOne({ _id: new mongoose.Types.ObjectId(messageId) });
    if (attachmentId) await mongoose.connection.db.collection('attachments').deleteOne({ _id: new mongoose.Types.ObjectId(attachmentId) });
    const userIds = [alice, bob, mallory].filter(Boolean).map((entry) => new mongoose.Types.ObjectId(entry.user.id));
    if (userIds.length) await mongoose.connection.db.collection('users').deleteMany({ _id: { $in: userIds } });
  } finally {
    if (context) await context.stop();
  }
});

async function transcriptRequest(user, payload) {
  const response = await fetch(`${context.base}/messages/${messageId}/transcription`, {
    method: 'POST',
    headers: authHeaders(user.token),
    body: JSON.stringify(payload),
  });
  return { status: response.status, body: await response.json() };
}

test('both DM participants manage only their own encrypted transcript entry', async () => {
  const bobClaim = await transcriptRequest(bob, { action: 'claim' });
  const aliceClaim = await transcriptRequest(alice, { action: 'claim' });
  assert.equal(bobClaim.status, 200);
  assert.equal(aliceClaim.status, 200);

  const bobToken = bobClaim.body.data.transcription.participant.claimToken;
  const aliceToken = aliceClaim.body.data.transcription.participant.claimToken;
  assert.ok(bobToken);
  assert.ok(aliceToken);
  const duplicateBobClaim = await transcriptRequest(bob, { action: 'claim' });
  assert.equal(duplicateBobClaim.status, 409);

  const bobEnvelope = sealMessage('bob local transcript', bob.keySet[0].publicKey);
  const crossTargetEnvelope = sealMessage('bob local transcript', alice.keySet[0].publicKey);
  const crossTarget = await transcriptRequest(bob, {
    action: 'commit',
    claimToken: bobToken,
    encryptedText: crossTargetEnvelope.ciphertext,
    nonce: crossTargetEnvelope.nonce,
    ephemeralPublicKey: crossTargetEnvelope.ephemeralPublicKey,
    targetPublicKey: crossTargetEnvelope.targetPublicKey,
  });
  assert.equal(crossTarget.status, 403);

  const bobCommit = await transcriptRequest(bob, {
    action: 'commit',
    claimToken: bobToken,
    status: 'completed',
    encryptedText: bobEnvelope.ciphertext,
    nonce: bobEnvelope.nonce,
    ephemeralPublicKey: bobEnvelope.ephemeralPublicKey,
    targetPublicKey: bobEnvelope.targetPublicKey,
  });
  assert.equal(bobCommit.status, 200);

  const aliceEnvelope = sealMessage('alice local transcript', alice.keySet[0].publicKey);
  const aliceCommit = await transcriptRequest(alice, {
    action: 'commit',
    claimToken: aliceToken,
    status: 'completed',
    encryptedText: aliceEnvelope.ciphertext,
    nonce: aliceEnvelope.nonce,
    ephemeralPublicKey: aliceEnvelope.ephemeralPublicKey,
    targetPublicKey: aliceEnvelope.targetPublicKey,
  });
  assert.equal(aliceCommit.status, 200);

  const outsider = await transcriptRequest(mallory, { action: 'claim' });
  assert.equal(outsider.status, 403);

  const stored = await mongoose.connection.db.collection('messages').findOne({
    _id: new mongoose.Types.ObjectId(messageId),
  });
  assert.equal(stored.transcription.entries.length, 2);
  const bobStored = stored.transcription.entries.find((entry) => String(entry.user) === bob.user.id);
  const aliceStored = stored.transcription.entries.find((entry) => String(entry.user) === alice.user.id);
  assert.equal(unsealMessage({ ...bobStored, ciphertext: bobStored.encryptedText }, bob.keySet[0].secretKey), 'bob local transcript');
  assert.equal(unsealMessage({ ...aliceStored, ciphertext: aliceStored.encryptedText }, alice.keySet[0].secretKey), 'alice local transcript');

  const bobView = toClientMessage(stored, bob.user.id);
  const aliceView = toClientMessage(stored, alice.user.id);
  assert.deepEqual(bobView.transcription.entries.map((entry) => entry.user), [bob.user.id]);
  assert.deepEqual(aliceView.transcription.entries.map((entry) => entry.user), [alice.user.id]);
  assert.equal(bobView.transcription.entries[0].claimToken, undefined);
  assert.equal(aliceView.transcription.entries[0].claimToken, undefined);
});