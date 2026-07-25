// Boots the real Express app against a throwaway in-memory MongoDB instance
// — no external database, secrets, or network dependency beyond downloading
// the mongod binary, which mongodb-memory-server handles itself. Safe to run
// in CI with zero configuration.
import http from 'http';
import mongoose from 'mongoose';
import { MongoMemoryServer } from 'mongodb-memory-server';
import { authHeaders } from './attacks.js';

export async function startTestServer(options = {}) {
  const mongod = await MongoMemoryServer.create();
  process.env.MONGODB_URI = mongod.getUri();
  process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-only-secret-never-used-in-production';
  process.env.QUANTUM_AI_SERVICE_SECRET =
    process.env.QUANTUM_AI_SERVICE_SECRET || 'test-only-quantum-ai-service-secret';
  process.env.UPLOAD_DIR = process.env.UPLOAD_DIR || '.test-uploads';
  process.env.CLIENT_URL =
    process.env.CLIENT_URL || 'http://localhost:5173,http://localhost:5175';

  const { connectDB } = await import('../../src/config/db.js');
  const { createApp } = await import('../../src/app.js');

  await connectDB();
  const app = createApp();
  const server = http.createServer((req, res) => app(req, res));

  let io;
  if (options.withSockets) {
    const { Server } = await import('socket.io');
    const { attachSocket } = await import('../../src/socket/index.js');
    const allowedOrigins = String(process.env.CLIENT_URL)
      .split(',')
      .map((origin) => origin.trim())
      .filter(Boolean);
    io = new Server(server, { cors: { origin: allowedOrigins } });
    attachSocket(io);
  }

  await new Promise((resolve) => server.listen(0, resolve));
  const { port } = server.address();

  return {
    base: `http://localhost:${port}/api`,
    origin: `http://localhost:${port}`,
    port,
    server,
    io,
    async stop() {
      if (io) await new Promise((resolve) => io.close(resolve));
      await new Promise((resolve) => server.close(resolve));
      await mongoose.disconnect();
      await mongod.stop();
    },
  };
}

export async function registerUser(base, username, extras = {}) {
  const { generateKeySet } = await import('./crypto.js');
  const keySet = generateKeySet();
  const res = await fetch(`${base}/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username,
      email: `${username}@example.com`,
      password: extras.password || 'password123',
      publicKeys: keySet.map((k) => k.publicKey),
      ...extras.body,
    }),
  }).then((r) => r.json());
  if (!res.success) throw new Error(`registerUser(${username}) failed: ${res.error}`);
  return { keySet, token: res.data.token, user: res.data.user, password: extras.password || 'password123' };
}

export async function login(base, email, password) {
  const res = await fetch(`${base}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  const body = await res.json().catch(() => ({}));
  return { status: res.status, body, token: body?.data?.token };
}

export async function createGroup(base, token, { name, memberIds, description, visibility, joinPolicy }) {
  const res = await fetch(`${base}/groups`, {
    method: 'POST',
    headers: authHeaders(token),
    body: JSON.stringify({ name, memberIds, description, visibility, joinPolicy }),
  }).then((r) => r.json());
  if (!res.success) throw new Error(`createGroup failed: ${res.error}`);
  return res.data;
}

export async function sendGroupMessage(base, token, groupId, envelopes, extras = {}) {
  const res = await fetch(`${base}/groups/${groupId}/messages`, {
    method: 'POST',
    headers: authHeaders(token),
    body: JSON.stringify(envelopes ? { envelopes, ...extras } : { ...extras }),
  });
  const body = await res.json().catch(() => ({}));
  return { status: res.status, body };
}

/** Build per-member sealed envelopes for a group plaintext. */
export async function sealGroupEnvelopes(plaintext, members) {
  const { sealMessage } = await import('./crypto.js');
  return members.map((member) => {
    const target = member.keySet[0];
    const sealed = sealMessage(plaintext, target.publicKey);
    return {
      user: member.user.id,
      ciphertext: sealed.ciphertext,
      nonce: sealed.nonce,
      ephemeralPublicKey: sealed.ephemeralPublicKey,
      targetPublicKey: sealed.targetPublicKey,
    };
  });
}
