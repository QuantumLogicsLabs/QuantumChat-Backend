import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import webpush from 'web-push';
import AppConfig from '../models/AppConfig.js';
import PushSubscription from '../models/PushSubscription.js';
import User from '../models/User.js';
import { toObjectId } from '../utils/toObjectId.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const VAPID_FILE = path.resolve(__dirname, '../../data/vapid-keys.json');
const VAPID_CONFIG_ID = 'vapid';

let vapidPublicKey = null;
let pushReady = false;
let initPromise = null;

function isWithinDoNotDisturb(dnd) {
  if (!dnd?.enabled) return false;
  const [startH, startM] = String(dnd.startTime || '22:00').split(':').map(Number);
  const [endH, endM] = String(dnd.endTime || '07:00').split(':').map(Number);
  const now = new Date();
  const nowMinutes = now.getHours() * 60 + now.getMinutes();
  const startMinutes = startH * 60 + startM;
  const endMinutes = endH * 60 + endM;
  if (startMinutes === endMinutes) return true;
  if (startMinutes < endMinutes) {
    return nowMinutes >= startMinutes && nowMinutes < endMinutes;
  }
  return nowMinutes >= startMinutes || nowMinutes < endMinutes;
}

function applyVapidKeys({ publicKey, privateKey, subject }) {
  webpush.setVapidDetails(subject, publicKey, privateKey);
  vapidPublicKey = publicKey;
  pushReady = true;
}

async function persistVapidToMongo({ publicKey, privateKey, subject }) {
  try {
    await AppConfig.findByIdAndUpdate(
      VAPID_CONFIG_ID,
      { publicKey, privateKey, subject, updatedAt: new Date() },
      { upsert: true, new: true, setDefaultsOnInsert: true },
    );
  } catch (err) {
    console.warn('[push] Could not persist VAPID keys to MongoDB:', err.message);
  }
}

function persistVapidToFile({ publicKey, privateKey, subject }) {
  try {
    fs.mkdirSync(path.dirname(VAPID_FILE), { recursive: true });
    fs.writeFileSync(
      VAPID_FILE,
      JSON.stringify(
        {
          publicKey,
          privateKey,
          subject,
          createdAt: new Date().toISOString(),
        },
        null,
        2,
      ),
      { mode: 0o600 },
    );
  } catch (err) {
    console.warn('[push] Could not persist VAPID keys to file:', err.message);
  }
}

async function loadOrCreateVapidKeys() {
  const subject = process.env.VAPID_SUBJECT || 'mailto:admin@quantumchat.local';
  const envPublic = process.env.VAPID_PUBLIC_KEY;
  const envPrivate = process.env.VAPID_PRIVATE_KEY;

  if (envPublic && envPrivate) {
    return { publicKey: envPublic, privateKey: envPrivate, subject, source: 'env' };
  }

  try {
    const saved = await AppConfig.findById(VAPID_CONFIG_ID).lean();
    if (saved?.publicKey && saved?.privateKey) {
      return {
        publicKey: saved.publicKey,
        privateKey: saved.privateKey,
        subject: saved.subject || subject,
        source: 'mongo',
      };
    }
  } catch (err) {
    console.warn('[push] Could not read VAPID keys from MongoDB:', err.message);
  }

  try {
    if (fs.existsSync(VAPID_FILE)) {
      const saved = JSON.parse(fs.readFileSync(VAPID_FILE, 'utf8'));
      if (saved?.publicKey && saved?.privateKey) {
        const keys = {
          publicKey: saved.publicKey,
          privateKey: saved.privateKey,
          subject: saved.subject || subject,
          source: 'file',
        };
        // Mirror file keys into Mongo so Vercel serverless stays stable.
        await persistVapidToMongo(keys);
        return keys;
      }
    }
  } catch (err) {
    console.warn('[push] Could not read saved VAPID keys:', err.message);
  }

  const generated = webpush.generateVAPIDKeys();
  const keys = {
    publicKey: generated.publicKey,
    privateKey: generated.privateKey,
    subject,
    source: 'generated',
  };
  await persistVapidToMongo(keys);
  persistVapidToFile(keys);
  console.warn(
    '[push] Generated VAPID keys and saved to MongoDB (and file when possible). ' +
      'For production, set VAPID_PUBLIC_KEY / VAPID_PRIVATE_KEY / VAPID_SUBJECT in .env.',
  );
  return keys;
}

async function initFromEnvAsync() {
  if (vapidPublicKey !== null && pushReady) return;
  if (initPromise) return initPromise;

  initPromise = (async () => {
    try {
      const keys = await loadOrCreateVapidKeys();
      applyVapidKeys(keys);
    } catch (err) {
      console.warn('[push] Failed to initialize web-push:', err.message);
      vapidPublicKey = vapidPublicKey || '';
      pushReady = false;
    }
  })();

  return initPromise;
}

// Best-effort sync init for local; serverless awaits in notify/getVapid.
initFromEnvAsync().catch(() => {});

export async function getVapidPublicKey() {
  await initFromEnvAsync();
  return vapidPublicKey || '';
}

export async function saveSubscription(userId, sub) {
  const endpoint = String(sub?.endpoint || '').trim();
  const p256dh = String(sub?.keys?.p256dh || '').trim();
  const auth = String(sub?.keys?.auth || '').trim();
  if (!endpoint || !p256dh || !auth) {
    const err = new Error('endpoint and keys.p256dh / keys.auth are required');
    err.status = 400;
    throw err;
  }

  await PushSubscription.findOneAndUpdate(
    { endpoint },
    {
      user: userId,
      endpoint,
      keys: { p256dh, auth },
      userAgent: String(sub?.userAgent || '').slice(0, 512),
      createdAt: new Date(),
    },
    { upsert: true, new: true, setDefaultsOnInsert: true },
  );
}

export async function removeSubscription(userId, endpoint) {
  const ep = String(endpoint || '').trim();
  if (!ep) {
    const err = new Error('endpoint is required');
    err.status = 400;
    throw err;
  }
  await PushSubscription.deleteOne({ user: userId, endpoint: ep });
}
async function isChatLockedFor(userId, conversationKey) {
      if (!conversationKey) return false;
      const user = await User.findById(userId).select('lockedChats').lean();
      return Boolean(user?.lockedChats?.some((l) => l.conversationKey === conversationKey));
    }

async function shouldSendPush(userId, payload) {
  const user = await User.findById(userId)
    .select('notificationSettings mutedChats')
    .lean();
  if (!user) return false;

  const ns = user.notificationSettings || {};
  if (ns.webNotifications?.enabled === false) return false;
  if (ns.priority === 'silent') return false;
  if (isWithinDoNotDisturb(ns.doNotDisturb)) return false;

  const kind = payload?.kind || 'dm';
  if (kind === 'dm') {
    if (ns.messageNotifications === 'off') return false;
  }
  if (kind === 'reaction') {
    if (ns.messageNotifications === 'all_except_reactions') return false;
  }
  if (kind === 'group') {
    const mode = ns.groupNotifications || 'all';
    if (mode === 'off') return false;
    if (mode === 'mentions_only' && !payload?.isMention) return false;
    if (mode === 'important_only' && !payload?.isMention && !payload?.isAnnouncement) return false
  }
  if (kind === 'live') {
    if (ns.liveNotifications === false) return false;
  }
  if (kind === 'call') {
    const cn = ns.callNotifications || {};
    if (cn.voiceCallEnabled === false && cn.videoCallEnabled === false) return false;
  }

  const convKey = payload?.conversationKey;
  if (convKey && Array.isArray(user.mutedChats)) {
    const now = Date.now();
    const muted = user.mutedChats.some((m) => {
      if (m.conversationKey !== convKey) return false;
      if (!m.expiresAt) return true;
      return new Date(m.expiresAt).getTime() > now;
    });
    if (muted) return false;
  }

  return true;
}

/**
 * Send an OS notification via Web Push.
 * Always attempted (not gated on Socket.IO "online") so alerts still appear
 * when the user is in another app (e.g. Cursor) with QuantumChat backgrounded.
 */
export async function notifyUser(userId, payload) {
  await initFromEnvAsync();
  if (!pushReady) {
    console.error('[push] Push service is not ready');
    return;
  }

  const uid = toObjectId(userId);
  if (!uid) {
    console.error('[push] Invalid user ID:', userId);
    return;
  }

  const allowed = await shouldSendPush(uid, payload).catch(() => true);
  if (!allowed) return;
  if (await isChatLockedFor(uid, payload?.conversationKey).catch(() => false)) {
      payload = {
        title: 'QuantumChat',
        body: 'New message',
        kind: 'dm',
        tag: 'quantumchat-locked',
        url: '/chat',
        silent: payload?.silent === true,
      };
    }

  const subs = await PushSubscription.find({ user: uid });
   if (!subs.length) {
    console.warn(`[push] No push subscriptions found for user ${uid}`);
    return;
  }

  // E2E: never put message plaintext or ciphertext into push payloads.
  const rawTitle = String(payload?.title || 'QuantumChat');
  const rawBody = String(payload?.body || 'New notification');
  const title = Array.from(rawTitle).slice(0, 64).join('');
  const bodyText = Array.from(rawBody).slice(0, 120).join('');
  if (/SECRET_E2E_|ciphertext|forRecipient|v=0/i.test(`${title}\n${bodyText}`)) {
    console.warn('[push] blocked unsafe notification payload');
    return;
  }

  const silent = payload?.silent === true;
  const body = JSON.stringify({
    title,
    body: bodyText,
    icon: '/logo.png',
    badge: '/logo.png',
    tag: payload?.tag || payload?.conversationKey || 'quantumchat',
    silent,
    requireInteraction: payload?.requireInteraction === true,
    url: payload?.url || '/chat',
     // Up to 2 actions render reliably across browsers; anything beyond
    // that is silently dropped by most implementations anyway.
    actions: Array.isArray(payload?.actions) ? payload.actions.slice(0, 2) : [],
    data: { url: payload?.url || '/chat', kind: payload?.kind || 'dm', ...(payload?.data || {}) },
  });

  await Promise.all(
    subs.map(async (sub) => {
      try {
        await webpush.sendNotification(
          {
            endpoint: sub.endpoint,
            keys: {
              p256dh: sub.keys.p256dh,
              auth: sub.keys.auth,
            },
          },
          body,
        );
      } catch (err) {
        const status = err?.statusCode || err?.status;
        if (status === 404 || status === 410) {
          // Subscription no longer exists on the push service at all.
          await PushSubscription.deleteOne({ _id: sub._id }).catch(() => {});
        } else if (status === 403) {
          // VAPID key mismatch — this subscription was created against a
          // different keypair than the server currently signs with (e.g.
          // after rotating/newly-configuring VAPID_PUBLIC_KEY/PRIVATE_KEY).
          // It will never succeed again with the current keys, so it's just
          // as dead as a 404/410 — clean it up the same way, but log it
          // distinctly since the fix differs (client needs to re-subscribe).
          console.error(
            `[push] VAPID mismatch (HTTP 403) for user ${userId}, subscription ${sub._id} — removing stale subscription. ` +
              'That account needs to click "Enable Browser Notifications" again to re-subscribe against the current server key.'
          );
          await PushSubscription.deleteOne({ _id: sub._id }).catch(() => {});
        } else {
          console.error(
            `[push] sendNotification failed for user ${userId}, subscription ${sub._id}:`,
            status ? `HTTP ${status}` : err?.message || err
          );
        }
      }
    }),
  );
}
