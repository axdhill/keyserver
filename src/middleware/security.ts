import { Request, Response, NextFunction } from 'express';
import rateLimit from 'express-rate-limit';

export const keyRetrievalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: 'Too many key retrieval requests, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: false
});

export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many authentication attempts, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: false
});

export const strictRateLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 100,
  message: 'API rate limit exceeded. Please wait before making more requests.',
  standardHeaders: true,
  legacyHeaders: false
});

export const validateRequestOrigin = (allowedOrigins: string[]) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    const origin = req.headers.origin || req.headers.referer;
    
    if (!origin && process.env.NODE_ENV === 'production') {
      res.status(403).json({ error: 'Origin validation failed' });
      return;
    }
    
    if (origin && allowedOrigins.length > 0 && !allowedOrigins.includes('*')) {
      const isAllowed = allowedOrigins.some(allowed => 
        origin.startsWith(allowed)
      );
      
      if (!isAllowed) {
        res.status(403).json({ error: 'Origin not allowed' });
        return;
      }
    }
    
    next();
  };
};

export const securityHeaders = (_req: Request, res: Response, next: NextFunction): void => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.removeHeader('X-Powered-By');
  next();
};