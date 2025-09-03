import crypto from 'crypto';

export const encryptKey = (key: string, secret: string): string => {
  const algorithm = 'aes-256-gcm';
  const iv = crypto.randomBytes(16);
  const salt = crypto.randomBytes(32);
  const derivedKey = crypto.pbkdf2Sync(secret, salt, 100000, 32, 'sha256');
  
  const cipher = crypto.createCipheriv(algorithm, derivedKey, iv);
  
  let encrypted = cipher.update(key, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  const authTag = cipher.getAuthTag();
  
  return JSON.stringify({
    encrypted,
    salt: salt.toString('hex'),
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex')
  });
};

export const decryptKey = (encryptedData: string, secret: string): string => {
  const algorithm = 'aes-256-gcm';
  const { encrypted, salt, iv, authTag } = JSON.parse(encryptedData);
  
  const derivedKey = crypto.pbkdf2Sync(
    secret,
    Buffer.from(salt, 'hex'),
    100000,
    32,
    'sha256'
  );
  
  const decipher = crypto.createDecipheriv(
    algorithm,
    derivedKey,
    Buffer.from(iv, 'hex')
  );
  
  decipher.setAuthTag(Buffer.from(authTag, 'hex'));
  
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  
  return decrypted;
};