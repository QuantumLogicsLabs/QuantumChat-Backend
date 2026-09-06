import cors from 'cors';
import express from 'express';
import helmet from 'helmet';
import mongoose from 'mongoose';
import { allowedOrigins } from './config/corsOrigins.js';
import { runBirthdayNotifications } from './jobs/birthdayNotifications.js';
import { runStoryPublishJobs } from './jobs/publishScheduledStories.js';
import { publicApiIpLimiter } from './middleware/apiKeyAuth.js';
import { authLimiter } from './middleware/rateLimiter.js';
import activityRoutes from './routes/activityRoutes.js';
import attachmentRoutes from './routes/attachmentRoutes.js';
import authRoutes from './routes/authRoutes.js';
import callSignalRoutes from './routes/callSignalRoutes.js';
import chatThemeRoutes from './routes/chatThemeRoutes.js';
import deviceLinkRoutes from './routes/deviceLinkRoutes.js';
import gifRoutes from './routes/gifRoutes.js';
import groupRoutes from './routes/groupRoutes.js';
import messageRoutes from './routes/messageRoutes.js';
import presenceRoutes from './routes/presenceRoutes.js';
import publicApiRoutes from './routes/publicApiRoutes.js';
import reportRoutes from './routes/reportRoutes.js';
import storyRoutes from './routes/storyRoutes.js';
import trustRoutes from './routes/trustRoutes.js';
import userRoutes from './routes/userRoutes.js';
import {
  getCloudinaryDiagnostics,
  hasCloudinaryCredentials,
} from './storage/cloudinaryEnv.js';
export function createApp() {
  const app = express();

  // Vercel (and most PaaS hosts) sit behind a reverse proxy and set
  // X-Forwarded-For. Without trust proxy enabled, express-rate-limit
  // refuses to trust that header and throws ERR_ERL_UNEXPECTED_X_FORWARDED_FOR
  // on every request, which was breaking /api/auth/* entirely.
  app.set('trust proxy', 1);

  // The API is deliberately consumed cross-origin (frontend dev server runs
  // on a different port), so the default same-origin resource policy would
  // block the browser from reading any response, including plain JSON.
  app.use(
    helmet({
      crossOriginResourcePolicy: { policy: 'cross-origin' },
      contentSecurityPolicy: {
        useDefaults: true,
        directives: {
          defaultSrc: ["'none'"],
          frameAncestors: ["'none'"],
          baseUri: ["'none'"],
          formAction: ["'none'"],
        },
      },
      referrerPolicy: { policy: 'no-referrer' },
      frameguard: { action: 'deny' },
      xContentTypeOptions: true,
    })
  );

  // Passing an Error into the cors callback used to become a 500 because the
  // Express error handler ignored err.status — browsers on ai.* saw login 500s.
  app.use(
    cors({
      origin(origin, callback) {
        if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
        // Deny without throwing — avoids turning CORS misses into HTTP 500.
        return callback(null, false);
      },
      methods: ['GET', 'HEAD', 'PUT', 'PATCH', 'POST', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-User-Id', 'X-API-Key', 'x-vault-token'],
      optionsSuccessStatus: 204,
    })
  );

  app.use(express.json({ limit: '100kb' }));
  app.use('/api/gifs', gifRoutes);
app.use('/api/activity', activityRoutes);
  app.get('/api/health', (req, res) => {
    const cloudinary = getCloudinaryDiagnostics();
    const mongoConnected = mongoose.connection.readyState === 1;
    res.json({
      success: true,
      data: {
        status: 'ok',
        cloudinaryConfigured: hasCloudinaryCredentials(),
        cloudinary,
        database: mongoConnected
          ? { connected: true, name: mongoose.connection.name, host: mongoose.connection.host }
          : { connected: false },
      },
    });
  });

  // Serverless-safe trigger for the birthday-notification sweep. server.js's
    // setInterval only runs on a persistent process (local dev / non-serverless
    // hosting); Vercel's api/index.js boots per-request and never keeps that
    // interval alive, so an external scheduler must call this route on a
    // schedule instead. Guarded by a shared secret since the caller is an
    // external scheduler, not a logged-in user.
    app.get('/api/cron/birthday', async (req, res) => {
      const provided = req.headers['x-cron-secret'] || req.query.secret;
      if (!process.env.CRON_SECRET || provided !== process.env.CRON_SECRET) {
        return res.status(401).json({ success: false, error: 'Unauthorized' });
      }
      try {
        const notifiedCount = await runBirthdayNotifications();
        res.json({ success: true, data: { notifiedCount } });
      } catch (err) {
        console.error('Birthday cron sweep failed:', err.message);
        res.status(500).json({ success: false, error: 'Sweep failed' });
      }
    });

    app.get('/api/cron/stories-publish', async (req, res) => {
      const provided = req.headers['x-cron-secret'] || req.query.secret;
      if (!process.env.CRON_SECRET || provided !== process.env.CRON_SECRET) {
        return res.status(401).json({ success: false, error: 'Unauthorized' });
      }
      try {
        const io = req.app.get('io');
        const publishedCount = await runStoryPublishJobs(io);
        res.json({ success: true, data: { publishedCount } });
      } catch (err) {
        console.error('Story publish cron failed:', err.message);
        res.status(500).json({ success: false, error: 'Sweep failed' });
      }
    });

  // Skip rate limiting on CORS preflight — OPTIONS must always be cheap/fast.
  app.use('/api/auth', (req, res, next) => {
    if (req.method === 'OPTIONS') return next();
    return authLimiter(req, res, next);
  }, authRoutes);
  app.use('/api/users/sessions/link', deviceLinkRoutes);
  app.use('/api/users', userRoutes);
  app.use('/api/messages', messageRoutes);
  app.use('/api/attachments', attachmentRoutes);
  app.use('/api/groups', groupRoutes);
  app.use('/api/stories', storyRoutes);
  app.use('/api/reports', reportRoutes);
  app.use('/api/trust', trustRoutes);
  app.use('/api/call-signals', callSignalRoutes);
  app.use('/api/presence', presenceRoutes);
  app.use('/api/chat-themes', chatThemeRoutes);
  // Server-to-server integration surface for other QuantumLogics sites,
  // authenticated with an X-API-Key header instead of a user JWT.
  app.use('/api/public/v1', (req, res, next) => {
    if (req.method === 'OPTIONS') return next();
    return publicApiIpLimiter(req, res, next);
  }, publicApiRoutes);

  app.use((req, res) => {
    res.status(404).json({ success: false, error: 'Not found' });
  });

  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    console.error(err);
    if (err?.code === 'LIMIT_UNEXPECTED_FILE') {
      return res.status(400).json({
        success: false,
        error: `Unexpected upload field: ${err.field || 'unknown'}`,
      });
    }
    if (err?.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ success: false, error: 'File too large' });
    }
    if (err?.name === 'MulterError') {
      return res.status(400).json({ success: false, error: err.message || 'Upload failed' });
    }
    const status = Number(err?.status || err?.statusCode) || 500;
    if (status >= 400 && status < 600 && status !== 500) {
      return res.status(status).json({
        success: false,
        error: err.message || 'Request failed',
      });
    }
    res.status(500).json({ success: false, error: 'Internal server error' });
  });

  return app;
}
