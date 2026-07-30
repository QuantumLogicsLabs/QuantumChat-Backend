import rateLimit from "express-rate-limit";

// Blunt brute-force/credential-stuffing attempts against auth endpoints
// without affecting normal chat traffic.
export const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => req.method === "OPTIONS",
  message: {
    success: false,
    error: "Too many attempts, please try again shortly",
  },
});

/** General authenticated API limiter (CodeQL missing-rate-limiting). */
export const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 120,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: "Too many requests, please try again shortly",
  },
});

/**
 * Dedicated budget for realtime message polling. This route mounts after
 * requireAuth, so key by user rather than IP to avoid users behind one NAT
 * consuming each other's polling allowance.
 */
export const syncLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 90,
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => req.method === "OPTIONS",
  keyGenerator: (req) => String(req.user._id),
  message: {
    success: false,
    error: "Too many sync requests, please try again shortly",
  },
});

/** Separate budget for short-lived encrypted call signaling polling. */
export const callSignalLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 120,
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => req.method === "OPTIONS",
  message: { success: false, error: "Too many call signaling requests" },
});

/** Separate budget for short-lived encrypted call signaling polling. */
export const callSignalLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 120,
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => req.method === 'OPTIONS',
  message: { success: false, error: 'Too many call signaling requests' },
});
