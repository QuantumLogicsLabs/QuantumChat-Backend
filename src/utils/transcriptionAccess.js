export function getDirectTranscriptTargetKey(message, userId) {
  if (!message || message.group) return null;

  const id = String(userId);
  if (String(message.from) === id) {
    return message.forSender?.targetPublicKey || null;
  }
  if (String(message.to) === id) {
    return message.forRecipient?.targetPublicKey || null;
  }
  return null;
}

export function isDirectTranscriptTargetAllowed(message, userId, targetPublicKey) {
  const expectedTargetPublicKey = getDirectTranscriptTargetKey(message, userId);
  return Boolean(
    expectedTargetPublicKey &&
    /^[0-9a-f]{64}$/i.test(targetPublicKey || '') &&
    String(targetPublicKey).toLowerCase() === String(expectedTargetPublicKey).toLowerCase(),
  );
}