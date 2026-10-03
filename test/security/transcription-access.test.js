import assert from 'node:assert/strict';
import test from 'node:test';

import {
  getDirectTranscriptTargetKey,
  isDirectTranscriptTargetAllowed,
} from '../../src/utils/transcriptionAccess.js';

test('direct transcript target key belongs to the authenticated message participant', () => {
  const message = {
    from: 'alice',
    to: 'bob',
    forSender: { targetPublicKey: 'alice-key' },
    forRecipient: { targetPublicKey: 'bob-key' },
  };

  assert.equal(getDirectTranscriptTargetKey(message, 'alice'), 'alice-key');
  assert.equal(getDirectTranscriptTargetKey(message, 'bob'), 'bob-key');
  assert.equal(getDirectTranscriptTargetKey(message, 'mallory'), null);
  assert.equal(isDirectTranscriptTargetAllowed(message, 'bob', 'bob-key'), false);
  assert.equal(isDirectTranscriptTargetAllowed(message, 'bob', 'a'.repeat(64)), false);
  message.forRecipient.targetPublicKey = 'b'.repeat(64);
  assert.equal(isDirectTranscriptTargetAllowed(message, 'bob', 'B'.repeat(64)), true);
});

test('group messages remain outside the direct-message transcript route', () => {
  const message = {
    from: 'alice',
    group: 'group-1',
    envelopes: [{ user: 'bob', targetPublicKey: 'bob-key' }],
  };

  assert.equal(getDirectTranscriptTargetKey(message, 'bob'), null);
});