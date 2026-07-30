import { test } from 'node:test';
import assert from 'node:assert/strict';
import { newObjectName } from '../../src/middleware/upload.js';

test('storage object names strip traversal characters from prefixes', () => {
  const name = newObjectName('../stories/../../outside', '.enc');
  assert.match(name, /^storiesoutside\/[0-9a-f-]+\.enc$/i);
  assert.equal(name.includes('..'), false);
  assert.equal(name.includes('\\'), false);
});

test('storage object names accept safe prefixes and extensions', () => {
  const name = newObjectName('avatars', '.JPG');
  assert.match(name, /^avatars\/[0-9a-f-]+\.jpg$/i);
});

test('storage object names reject unsafe extensions', () => {
  const name = newObjectName('avatars', '.svg/onload');
  assert.match(name, /^avatars\/[0-9a-f-]+$/i);
});
