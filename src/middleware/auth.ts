import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import { TokenPayload, ApiKeyPayload } from '../types';

declare global {
  namespace Express {
    interface Request {
      user?: TokenPayload;
      apiKeyData?: ApiKeyPayload;
    }
  }
}

const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');

export const generateApiKey = (): string => {
  return `ks_${crypto.randomBytes(32).toString('hex')}`;
};

export const hashPassword = async (password: string): Promise<string> => {
  return bcrypt.hash(password, 12);
};

export const verifyPassword = async (password: string, hash: string): Promise<boolean> => {
  return bcrypt.compare(password, hash);
};

export const generateToken = (payload: TokenPayload): string => {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '24h' });
};

export const verifyToken = (token: string): TokenPayload => {
  return jwt.verify(token, JWT_SECRET) as TokenPayload;
};

export const validateJWT = (req: Request, res: Response, next: NextFunction): void => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader?.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Missing or invalid authorization header' });
    return;
  }

  const token = authHeader.substring(7);

  try {
    const payload = verifyToken(token);
    req.user = payload;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
};

export const validateApiKey = (req: Request, res: Response, next: NextFunction): void => {
  const apiKey = req.headers['x-api-key'] as string;
  
  if (!apiKey) {
    res.status(401).json({ error: 'API key required' });
    return;
  }

  const validApiKeys = JSON.parse(process.env.VALID_API_KEYS || '{}');
  
  if (!validApiKeys[apiKey]) {
    res.status(401).json({ error: 'Invalid API key' });
    return;
  }

  req.apiKeyData = {
    apiKey,
    userId: validApiKeys[apiKey]
  };
  
  next();
};