function storageKey(userId) {
  return `qc_ai_capsules_${userId}`;
}

function canonicalCapsulePayload({ messagesTexts, purpose }) {
  const messages = Array.isArray(messagesTexts)
    ? messagesTexts.map((text) => String(text ?? ''))
    : [];
  return {
    messages,
    purpose: String(purpose || 'assist'),
  };
}

async function sha256Hex(text) {
  const data = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Build a sealed AI context capsule: plaintext stays on-device;
 * only contentHash is meant for server receipts.
 */
export async function buildCapsule({ messagesTexts, purpose }) {
  const payload = canonicalCapsulePayload({ messagesTexts, purpose });
  const plaintextJson = JSON.stringify(payload);
  const contentHash = await sha256Hex(plaintextJson);
  return { plaintextJson, contentHash };
}

export function getLocalConsentLog(userId) {
  if (!userId || typeof localStorage === 'undefined') return [];
  try {
    const raw = localStorage.getItem(storageKey(userId));
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export function saveLocalConsentLog(userId, entry) {
  if (!userId || typeof localStorage === 'undefined') return;
  const prev = getLocalConsentLog(userId);
  const next = [entry, ...prev].slice(0, 50);
  localStorage.setItem(storageKey(userId), JSON.stringify(next));
}
