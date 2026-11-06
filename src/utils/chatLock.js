/**
 * True when `key` (a conversationKey such as "dm:<a>:<b>" or "group:<id>") is
 * in the user's Chat Lock list. Accepts a Mongoose doc or a lean/plain user.
 */
export function isConversationLocked(user, key) {
  if (!user || !key || !Array.isArray(user.lockedChats)) return false;
  return user.lockedChats.some((l) => l && l.conversationKey === key);
}
