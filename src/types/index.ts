export interface User {
  id: string;
  username: string;
  passwordHash: string;
  apiKey: string;
  createdAt: Date;
  lastAccess: Date;
}

export interface TokenPayload {
  userId: string;
  username: string;
  iat?: number;
  exp?: number;
}

export interface ApiKeyPayload {
  apiKey: string;
  userId: string;
}

export interface KeyService {
  openai?: string;
  anthropic?: string;
}