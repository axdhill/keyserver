# Secure API Key Server

A secure proxy service for managing and serving OpenAI and Anthropic API keys with encryption and authentication.

## Features

- **Secure Authentication**: Master key registration system with JWT tokens
- **API Key Management**: Secure storage and retrieval of OpenAI and Anthropic keys
- **Encryption**: AES-256-GCM encryption with PBKDF2 key derivation
- **Rate Limiting**: Multiple layers of rate limiting for security
- **Security Headers**: Comprehensive security headers and CORS protection
- **API Key Rotation**: Built-in key rotation functionality
- **Health Checks**: Railway-compatible health endpoint

## Security Architecture

### Authentication Flow
1. Register with master key to create user account
2. Receive unique API key for your applications
3. Use API key to retrieve encrypted service keys
4. Decrypt keys client-side using your API key

### Encryption
- Keys are encrypted using AES-256-GCM
- PBKDF2 key derivation with 100,000 iterations
- Each encryption includes unique salt and IV
- Authentication tags prevent tampering

### Rate Limiting
- General: 100 requests per 15 minutes
- Authentication: 5 attempts per 15 minutes  
- Key retrieval: 10 requests per minute

## API Endpoints

### Authentication

#### Register User
```http
POST /api/auth/register
Content-Type: application/json

{
  "username": "your-username",
  "password": "secure-password",
  "masterKey": "master-key-from-env"
}
```

#### Login
```http
POST /api/auth/login
Content-Type: application/json

{
  "username": "your-username",
  "password": "your-password"
}
```

#### Rotate API Key
```http
POST /api/auth/rotate-api-key
Content-Type: application/json

{
  "username": "your-username",
  "password": "your-password"
}
```

### Key Retrieval

#### Get OpenAI Key
```http
GET /api/keys/openai
X-API-Key: your-api-key
```

#### Get Anthropic Key
```http
GET /api/keys/anthropic
X-API-Key: your-api-key
```

#### Get All Keys
```http
GET /api/keys/all
X-API-Key: your-api-key
```

#### Test Decryption
```http
POST /api/keys/decrypt-test
Content-Type: application/json
X-API-Key: your-api-key

{
  "encryptedData": "encrypted-key-data",
  "secret": "your-api-key"
}
```

## Client Implementation

### JavaScript/TypeScript Example
```typescript
async function getApiKey(service: 'openai' | 'anthropic') {
  const response = await fetch(`https://your-server.railway.app/api/keys/${service}`, {
    headers: {
      'X-API-Key': 'your-api-key'
    }
  });
  
  const data = await response.json();
  const decryptedKey = await decryptKey(data.encryptedKey, 'your-api-key');
  return decryptedKey;
}

async function decryptKey(encryptedData: string, secret: string): Promise<string> {
  const { encrypted, salt, iv, authTag } = JSON.parse(encryptedData);
  
  // Derive key using PBKDF2
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  
  const key = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: hexToBuffer(salt),
      iterations: 100000,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );
  
  // Decrypt
  const decrypted = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: hexToBuffer(iv),
      additionalData: new ArrayBuffer(0),
      tagLength: 128
    },
    key,
    hexToBuffer(encrypted + authTag)
  );
  
  return new TextDecoder().decode(decrypted);
}
```

## Deployment on Railway

1. Create a new Railway project
2. Connect this GitHub repository
3. Set environment variables in Railway:
   - `MASTER_KEY`: Secure master key for user registration
   - `JWT_SECRET`: Secret for JWT tokens (auto-generated if not set)
   - `ENCRYPTION_SECRET`: Additional encryption layer (optional)
   - `OPENAI_API_KEY`: Your OpenAI API key
   - `ANTHROPIC_API_KEY`: Your Anthropic API key
   - `ALLOWED_ORIGINS`: Comma-separated list of allowed origins
   - `VALID_API_KEYS`: {} (will be managed by the app)
4. Deploy!

## Local Development

```bash
# Install dependencies
npm install

# Create .env file
cp .env.example .env
# Edit .env with your keys

# Development mode
npm run dev

# Build
npm run build

# Production
npm start
```

## Security Best Practices

1. **Never expose master key**: Keep it secure and rotate regularly
2. **Use HTTPS only**: Never send API keys over unencrypted connections
3. **Rotate keys regularly**: Use the rotation endpoint periodically
4. **Monitor access**: Check logs for suspicious activity
5. **Limit origins**: Configure ALLOWED_ORIGINS restrictively
6. **Client-side decryption**: Always decrypt keys on the client
7. **Secure storage**: Never store decrypted keys in localStorage

## License

MIT