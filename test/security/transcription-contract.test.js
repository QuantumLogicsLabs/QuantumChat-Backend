import test from 'node:test';
import assert from 'node:assert/strict';
import Message from '../../src/models/Message.js';

test('message schema supports encrypted transcription metadata with a pinned model target', () => {
  const actual = Message.schema.obj.transcription;
  assert.ok(actual, 'transcription should be in the schema object');

  const statusPath = Message.schema.path('transcription.status');
  const modelPath = Message.schema.path('transcription.model');
  const revisionPath = Message.schema.path('transcription.revision');
  const encryptedTextPath = Message.schema.path('transcription.encryptedText');
  const entriesPath = Message.schema.path('transcription.entries');

  assert.ok(statusPath, 'transcription processing state must be stored');
  assert.ok(modelPath, 'transcription model metadata must be stored');
  assert.ok(revisionPath, 'transcription model revision must be stored');
  assert.ok(encryptedTextPath, 'transcription ciphertext envelope must be stored');
  assert.ok(entriesPath, 'participant-specific transcript envelopes must be stored');

  assert.equal(actual.model.type, String, 'model should be a string');
  assert.equal(actual.revision.type, String, 'revision should be persisted as a string');
  assert.equal(actual.status.default, 'completed', 'completed transcriptions should default to completed');
  assert.equal(actual.revision.default, '5332fcc35e32a33b86612b9a57a89be7906102b1', 'model revision must be pinned to the Xenova whisper tiny commit');
  assert.ok(Message.schema.path('transcription.entries.user'));
  assert.ok(Message.schema.path('transcription.entries.encryptedText'));
  assert.ok(Message.schema.path('transcription.entries.targetPublicKey'));
});
