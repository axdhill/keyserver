export interface App {
  id: string;
  name: string;
  apiKey: string;
  permissions: {
    openai: boolean;
    anthropic: boolean;
  };
  allowedIPs?: string[];
  allowedDomains?: string[];
  rateLimit?: {
    windowMs: number;
    maxRequests: number;
  };
  createdAt: Date;
  lastAccess?: Date;
  accessCount: number;
  environment: 'development' | 'staging' | 'production';
  expiresAt?: Date;
}

export interface AppConfig {
  apps: Record<string, App>;
}