import { Router, Request, Response } from 'express';
import { generateApiKey, hashPassword, verifyPassword, generateToken } from '../middleware/auth';
import crypto from 'crypto';

export const authRouter = Router();

const users = new Map<string, any>();

authRouter.post('/register', async (req: Request, res: Response): Promise<void> => {
  try {
    const { username, password, masterKey } = req.body;

    if (!username || !password || !masterKey) {
      res.status(400).json({ error: 'Username, password, and master key are required' });
      return;
    }

    if (masterKey !== process.env.MASTER_KEY) {
      res.status(403).json({ error: 'Invalid master key' });
      return;
    }

    if (users.has(username)) {
      res.status(409).json({ error: 'Username already exists' });
      return;
    }

    const userId = crypto.randomUUID();
    const passwordHash = await hashPassword(password);
    const apiKey = generateApiKey();

    const user = {
      id: userId,
      username,
      passwordHash,
      apiKey,
      createdAt: new Date(),
      lastAccess: new Date()
    };

    users.set(username, user);

    const currentApiKeys = JSON.parse(process.env.VALID_API_KEYS || '{}');
    currentApiKeys[apiKey] = userId;
    process.env.VALID_API_KEYS = JSON.stringify(currentApiKeys);

    res.status(201).json({
      userId,
      username,
      apiKey,
      message: 'User registered successfully'
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

authRouter.post('/login', async (req: Request, res: Response): Promise<void> => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      res.status(400).json({ error: 'Username and password are required' });
      return;
    }

    const user = users.get(username);

    if (!user) {
      res.status(401).json({ error: 'Invalid credentials' });
      return;
    }

    const isValid = await verifyPassword(password, user.passwordHash);

    if (!isValid) {
      res.status(401).json({ error: 'Invalid credentials' });
      return;
    }

    user.lastAccess = new Date();

    const token = generateToken({
      userId: user.id,
      username: user.username
    });

    res.json({
      token,
      apiKey: user.apiKey,
      expiresIn: '24h'
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

authRouter.post('/rotate-api-key', async (req: Request, res: Response): Promise<void> => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      res.status(400).json({ error: 'Username and password are required' });
      return;
    }

    const user = users.get(username);

    if (!user) {
      res.status(401).json({ error: 'Invalid credentials' });
      return;
    }

    const isValid = await verifyPassword(password, user.passwordHash);

    if (!isValid) {
      res.status(401).json({ error: 'Invalid credentials' });
      return;
    }

    const currentApiKeys = JSON.parse(process.env.VALID_API_KEYS || '{}');
    delete currentApiKeys[user.apiKey];

    const newApiKey = generateApiKey();
    user.apiKey = newApiKey;
    currentApiKeys[newApiKey] = user.id;
    process.env.VALID_API_KEYS = JSON.stringify(currentApiKeys);

    res.json({
      apiKey: newApiKey,
      message: 'API key rotated successfully'
    });
  } catch (error) {
    console.error('API key rotation error:', error);
    res.status(500).json({ error: 'API key rotation failed' });
  }
});