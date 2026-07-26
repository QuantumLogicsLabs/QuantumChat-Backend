import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import authRoutes from './routes/authRoutes.js';
import userRoutes from './routes/userRoutes.js';
import messageRoutes from './routes/messageRoutes.js';
import attachmentRoutes from './routes/attachmentRoutes.js';
import groupRoutes from './routes/groupRoutes.js';
import storyRoutes from './routes/storyRoutes.js';
import trustRoutes from './routes/trustRoutes.js';
import { authLimiter } from './middleware/rateLimiter.js';

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

  // Always allow known Quantum product frontends, then merge CLIENT_URL / CORS_ORIGINS.
  // Passing an Error into the cors callback used to become a 500 because the
  // Express error handler ignored err.status — browsers on ai.* saw login 500s.
  const allowedOrigins = [
    ...new Set(
      [
        'http://localhost:5173',
        'http://localhost:5174',
        'http://localhost:5175',
        'https://chat.quantumlogicslimited.com',
        'https://ai.quantumlogicslimited.com',
        'https://quantum-chat.vercel.app',
        'https://quantum-chat-frontend.vercel.app',
        'https://quantum-chat-frontend-mu.vercel.app',
        'https://quantum-ai-frontend.vercel.app',
        ...String(process.env.CLIENT_URL || '')
          .split(',')
          .map((origin) => origin.trim())
          .filter(Boolean),
        ...String(process.env.CORS_ORIGINS || '')
          .split(',')
          .map((origin) => origin.trim())
          .filter(Boolean),
      ]
    ),
  ];
  app.use(
    cors({
      origin(origin, callback) {
        if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
        // Deny without throwing — avoids turning CORS misses into HTTP 500.
        return callback(null, false);
      },
      methods: ['GET', 'HEAD', 'PUT', 'PATCH', 'POST', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-User-Id'],
      optionsSuccessStatus: 204,
    })
  );
  app.use(express.json({ limit: '100kb' }));

  app.get('/api/health', (req, res) => res.json({ success: true, data: { status: 'ok' } }));

  // Skip rate limiting on CORS preflight — OPTIONS must always be cheap/fast.
  app.use('/api/auth', (req, res, next) => {
    if (req.method === 'OPTIONS') return next();
    return authLimiter(req, res, next);
  }, authRoutes);
  app.use('/api/users', userRoutes);
  app.use('/api/messages', messageRoutes);
  app.use('/api/attachments', attachmentRoutes);
  app.use('/api/groups', groupRoutes);
  app.use('/api/stories', storyRoutes);
  app.use('/api/trust', trustRoutes);

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
