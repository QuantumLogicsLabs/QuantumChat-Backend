import rateLimit from 'express-rate-limit';

// Blunt brute-force/credential-stuffing attempts against auth endpoints
// without affecting normal chat traffic.
export const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => req.method === 'OPTIONS',
  message: { success: false, error: 'Too many attempts, please try again shortly' },
});

/** General authenticated API limiter (CodeQL missing-rate-limiting). */
export const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 120,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Too many requests, please try again shortly' },
});
