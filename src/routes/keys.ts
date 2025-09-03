import { Router, Request, Response } from 'express';
import { encryptKey, decryptKey } from '../utils/encryption';

export const keysRouter = Router();

keysRouter.get('/openai', async (req: Request, res: Response): Promise<void> => {
  try {
    const apiKeyData = req.apiKeyData;
    
    if (!apiKeyData) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }

    const openaiKey = process.env.OPENAI_API_KEY;
    
    if (!openaiKey) {
      res.status(404).json({ error: 'OpenAI API key not configured' });
      return;
    }

    const encryptionSecret = process.env.ENCRYPTION_SECRET || apiKeyData.apiKey;
    const encryptedKey = encryptKey(openaiKey, encryptionSecret);

    res.json({
      service: 'openai',
      encryptedKey,
      hint: 'Decrypt using PBKDF2-derived AES-256-GCM with your API key',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Error fetching OpenAI key:', error);
    res.status(500).json({ error: 'Failed to retrieve key' });
  }
});

keysRouter.get('/anthropic', async (req: Request, res: Response): Promise<void> => {
  try {
    const apiKeyData = req.apiKeyData;
    
    if (!apiKeyData) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }

    const anthropicKey = process.env.ANTHROPIC_API_KEY;
    
    if (!anthropicKey) {
      res.status(404).json({ error: 'Anthropic API key not configured' });
      return;
    }

    const encryptionSecret = process.env.ENCRYPTION_SECRET || apiKeyData.apiKey;
    const encryptedKey = encryptKey(anthropicKey, encryptionSecret);

    res.json({
      service: 'anthropic',
      encryptedKey,
      hint: 'Decrypt using PBKDF2-derived AES-256-GCM with your API key',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Error fetching Anthropic key:', error);
    res.status(500).json({ error: 'Failed to retrieve key' });
  }
});

keysRouter.get('/all', async (req: Request, res: Response): Promise<void> => {
  try {
    const apiKeyData = req.apiKeyData;
    
    if (!apiKeyData) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }

    const keys: any = {};
    const encryptionSecret = process.env.ENCRYPTION_SECRET || apiKeyData.apiKey;

    if (process.env.OPENAI_API_KEY) {
      keys.openai = encryptKey(process.env.OPENAI_API_KEY, encryptionSecret);
    }

    if (process.env.ANTHROPIC_API_KEY) {
      keys.anthropic = encryptKey(process.env.ANTHROPIC_API_KEY, encryptionSecret);
    }

    if (Object.keys(keys).length === 0) {
      res.status(404).json({ error: 'No API keys configured' });
      return;
    }

    res.json({
      keys,
      hint: 'Decrypt using PBKDF2-derived AES-256-GCM with your API key',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Error fetching keys:', error);
    res.status(500).json({ error: 'Failed to retrieve keys' });
  }
});

keysRouter.post('/decrypt-test', async (req: Request, res: Response): Promise<void> => {
  try {
    const { encryptedData, secret } = req.body;

    if (!encryptedData || !secret) {
      res.status(400).json({ error: 'encryptedData and secret are required' });
      return;
    }

    try {
      const decrypted = decryptKey(encryptedData, secret);
      res.json({ 
        success: true,
        message: 'Decryption successful',
        keyPrefix: decrypted.substring(0, 8) + '...'
      });
    } catch (decryptError) {
      res.status(400).json({ 
        success: false,
        error: 'Decryption failed. Check your secret.'
      });
    }
  } catch (error) {
    console.error('Decrypt test error:', error);
    res.status(500).json({ error: 'Decryption test failed' });
  }
});