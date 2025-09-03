import { Router, Request, Response } from 'express';
import { validateAppKey, checkAppPermission } from '../middleware/appAuth';
import { encryptKey } from '../utils/encryption';

export const appsRouter = Router();

// All routes require app authentication
appsRouter.use(validateAppKey);

appsRouter.get('/keys/openai', checkAppPermission('openai'), async (req: Request, res: Response): Promise<void> => {
  try {
    const app = req.appData;
    if (!app) {
      res.status(401).json({ error: 'App not authenticated' });
      return;
    }

    const openaiKey = process.env.OPENAI_API_KEY;
    if (!openaiKey) {
      res.status(404).json({ error: 'OpenAI API key not configured' });
      return;
    }

    // Use app's API key as encryption secret for consistency
    const encryptedKey = encryptKey(openaiKey, app.apiKey);

    res.json({
      service: 'openai',
      encryptedKey,
      app: app.name,
      environment: app.environment,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Error fetching OpenAI key for app:', error);
    res.status(500).json({ error: 'Failed to retrieve key' });
  }
});

appsRouter.get('/keys/anthropic', checkAppPermission('anthropic'), async (req: Request, res: Response): Promise<void> => {
  try {
    const app = req.appData;
    if (!app) {
      res.status(401).json({ error: 'App not authenticated' });
      return;
    }

    const anthropicKey = process.env.ANTHROPIC_API_KEY;
    if (!anthropicKey) {
      res.status(404).json({ error: 'Anthropic API key not configured' });
      return;
    }

    const encryptedKey = encryptKey(anthropicKey, app.apiKey);

    res.json({
      service: 'anthropic',
      encryptedKey,
      app: app.name,
      environment: app.environment,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Error fetching Anthropic key for app:', error);
    res.status(500).json({ error: 'Failed to retrieve key' });
  }
});

appsRouter.get('/keys/all', async (req: Request, res: Response): Promise<void> => {
  try {
    const app = req.appData;
    if (!app) {
      res.status(401).json({ error: 'App not authenticated' });
      return;
    }

    const keys: any = {};

    if (app.permissions.openai && process.env.OPENAI_API_KEY) {
      keys.openai = encryptKey(process.env.OPENAI_API_KEY, app.apiKey);
    }

    if (app.permissions.anthropic && process.env.ANTHROPIC_API_KEY) {
      keys.anthropic = encryptKey(process.env.ANTHROPIC_API_KEY, app.apiKey);
    }

    if (Object.keys(keys).length === 0) {
      res.status(404).json({ error: 'No accessible keys for this app' });
      return;
    }

    res.json({
      keys,
      app: app.name,
      environment: app.environment,
      permissions: app.permissions,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Error fetching keys for app:', error);
    res.status(500).json({ error: 'Failed to retrieve keys' });
  }
});

appsRouter.get('/status', async (req: Request, res: Response): Promise<void> => {
  const app = req.appData;
  if (!app) {
    res.status(401).json({ error: 'App not authenticated' });
    return;
  }

  res.json({
    app: {
      name: app.name,
      environment: app.environment,
      permissions: app.permissions,
      accessCount: app.accessCount,
      lastAccess: app.lastAccess,
      rateLimit: app.rateLimit,
      expiresAt: app.expiresAt
    }
  });
});