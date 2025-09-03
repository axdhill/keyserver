import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { App, AppConfig } from '../types/app';
import rateLimit from 'express-rate-limit';

declare global {
  namespace Express {
    interface Request {
      appData?: App;
    }
  }
}

const APPS_CONFIG_PATH = process.env.APPS_CONFIG_PATH || path.join(__dirname, '../config/apps.json');

let appsCache: AppConfig | null = null;
let cacheTimestamp = 0;
const CACHE_TTL = 60000; // 1 minute cache

function loadApps(): AppConfig {
  const now = Date.now();
  if (appsCache && (now - cacheTimestamp) < CACHE_TTL) {
    return appsCache;
  }

  try {
    const configData = fs.readFileSync(APPS_CONFIG_PATH, 'utf8');
    appsCache = JSON.parse(configData);
    cacheTimestamp = now;
    return appsCache!;
  } catch (error) {
    console.error('Error loading apps config:', error);
    return { apps: {} };
  }
}

function saveApps(config: AppConfig): void {
  try {
    fs.writeFileSync(APPS_CONFIG_PATH, JSON.stringify(config, null, 2));
    appsCache = config;
    cacheTimestamp = Date.now();
  } catch (error) {
    console.error('Error saving apps config:', error);
  }
}

export function generateAppApiKey(): string {
  return `app_${crypto.randomBytes(32).toString('hex')}`;
}

export function registerApp(
  name: string,
  permissions: { openai: boolean; anthropic: boolean },
  options?: {
    allowedIPs?: string[];
    allowedDomains?: string[];
    rateLimit?: { windowMs: number; maxRequests: number };
    environment?: 'development' | 'staging' | 'production';
    expiresAt?: Date;
  }
): App {
  const config = loadApps();
  const id = crypto.randomUUID();
  const apiKey = generateAppApiKey();

  const app: App = {
    id,
    name,
    apiKey,
    permissions,
    allowedIPs: options?.allowedIPs,
    allowedDomains: options?.allowedDomains,
    rateLimit: options?.rateLimit || { windowMs: 60000, maxRequests: 30 },
    createdAt: new Date(),
    accessCount: 0,
    environment: options?.environment || 'production',
    expiresAt: options?.expiresAt
  };

  config.apps[apiKey] = app;
  saveApps(config);

  return app;
}

export function validateAppKey(req: Request, res: Response, next: NextFunction): void {
  const apiKey = req.headers['x-app-key'] as string || req.headers['x-api-key'] as string;

  if (!apiKey) {
    res.status(401).json({ error: 'App API key required' });
    return;
  }

  const config = loadApps();
  const app = config.apps[apiKey];

  if (!app) {
    res.status(401).json({ error: 'Invalid app API key' });
    return;
  }

  // Check if expired
  if (app.expiresAt && new Date(app.expiresAt) < new Date()) {
    res.status(401).json({ error: 'App API key expired' });
    return;
  }

  // IP whitelist check
  if (app.allowedIPs && app.allowedIPs.length > 0) {
    const clientIP = req.ip || req.socket.remoteAddress;
    if (!clientIP || !app.allowedIPs.includes(clientIP)) {
      res.status(403).json({ error: 'Access denied from this IP' });
      return;
    }
  }

  // Domain check for browser apps
  if (app.allowedDomains && app.allowedDomains.length > 0) {
    const origin = req.headers.origin || req.headers.referer;
    if (origin) {
      const allowed = app.allowedDomains.some(domain => 
        origin.includes(domain)
      );
      if (!allowed) {
        res.status(403).json({ error: 'Access denied from this domain' });
        return;
      }
    }
  }

  // Update access stats
  app.lastAccess = new Date();
  app.accessCount++;
  config.apps[apiKey] = app;
  saveApps(config);

  req.appData = app;
  next();
}

export function checkAppPermission(service: 'openai' | 'anthropic') {
  return (req: Request, res: Response, next: NextFunction): void => {
    const app = req.appData;

    if (!app) {
      res.status(401).json({ error: 'App authentication required' });
      return;
    }

    if (!app.permissions[service]) {
      res.status(403).json({ error: `App does not have permission to access ${service} keys` });
      return;
    }

    next();
  };
}

export function createAppRateLimiter(app: App) {
  return rateLimit({
    windowMs: app.rateLimit?.windowMs || 60000,
    max: app.rateLimit?.maxRequests || 30,
    message: 'App rate limit exceeded',
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => req.appData?.id || 'unknown'
  });
}