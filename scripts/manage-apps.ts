#!/usr/bin/env ts-node

import { registerApp, generateAppApiKey } from '../src/middleware/appAuth';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

const APPS_CONFIG_PATH = path.join(__dirname, '../src/config/apps.json');

interface CLIOptions {
  name: string;
  openai?: boolean;
  anthropic?: boolean;
  ips?: string;
  domains?: string;
  env?: 'development' | 'staging' | 'production';
  rateLimit?: string;
  expires?: string;
}

function parseArgs(): { command: string; options: CLIOptions } {
  const args = process.argv.slice(2);
  const command = args[0];
  const options: any = { name: '' };

  for (let i = 1; i < args.length; i++) {
    const arg = args[i];
    if (arg.startsWith('--')) {
      const key = arg.slice(2);
      const value = args[i + 1];
      if (key === 'name') options.name = value;
      if (key === 'openai') options.openai = true;
      if (key === 'anthropic') options.anthropic = true;
      if (key === 'ips') options.ips = value;
      if (key === 'domains') options.domains = value;
      if (key === 'env') options.env = value;
      if (key === 'rate-limit') options.rateLimit = value;
      if (key === 'expires') options.expires = value;
      if (value && !value.startsWith('--')) i++;
    }
  }

  return { command, options };
}

function registerNewApp(options: CLIOptions) {
  if (!options.name) {
    console.error('❌ App name is required (--name <app-name>)');
    process.exit(1);
  }

  const permissions = {
    openai: options.openai || false,
    anthropic: options.anthropic || false
  };

  if (!permissions.openai && !permissions.anthropic) {
    console.error('❌ At least one service permission required (--openai or --anthropic)');
    process.exit(1);
  }

  const appOptions: any = {
    environment: options.env || 'production'
  };

  if (options.ips) {
    appOptions.allowedIPs = options.ips.split(',').map(ip => ip.trim());
  }

  if (options.domains) {
    appOptions.allowedDomains = options.domains.split(',').map(d => d.trim());
  }

  if (options.rateLimit) {
    const [requests, minutes] = options.rateLimit.split('/').map(v => parseInt(v));
    appOptions.rateLimit = {
      windowMs: minutes * 60 * 1000,
      maxRequests: requests
    };
  }

  if (options.expires) {
    const days = parseInt(options.expires);
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + days);
    appOptions.expiresAt = expiresAt;
  }

  const app = registerApp(options.name, permissions, appOptions);

  console.log('✅ App registered successfully!\n');
  console.log('App Details:');
  console.log('═══════════════════════════════════════════════════════');
  console.log(`Name:        ${app.name}`);
  console.log(`App ID:      ${app.id}`);
  console.log(`API Key:     ${app.apiKey}`);
  console.log(`Environment: ${app.environment}`);
  console.log(`Permissions: OpenAI: ${permissions.openai ? '✓' : '✗'}, Anthropic: ${permissions.anthropic ? '✓' : '✗'}`);
  
  if (app.allowedIPs) {
    console.log(`IP Whitelist: ${app.allowedIPs.join(', ')}`);
  }
  
  if (app.allowedDomains) {
    console.log(`Allowed Domains: ${app.allowedDomains.join(', ')}`);
  }
  
  if (app.rateLimit) {
    console.log(`Rate Limit:  ${app.rateLimit.maxRequests} requests per ${app.rateLimit.windowMs / 60000} minutes`);
  }
  
  if (app.expiresAt) {
    console.log(`Expires:     ${app.expiresAt}`);
  }
  
  console.log('═══════════════════════════════════════════════════════\n');
  console.log('⚠️  Save this API key securely - it cannot be retrieved later!');
  console.log('\nUsage in your app:');
  console.log('```javascript');
  console.log(`fetch('https://your-server.railway.app/api/app/keys/all', {`);
  console.log(`  headers: { 'X-App-Key': '${app.apiKey}' }`);
  console.log('})');
  console.log('```');
}

function listApps() {
  try {
    const config = JSON.parse(fs.readFileSync(APPS_CONFIG_PATH, 'utf8'));
    const apps = Object.values(config.apps);

    if (apps.length === 0) {
      console.log('No apps registered yet.');
      return;
    }

    console.log('\nRegistered Apps:');
    console.log('═══════════════════════════════════════════════════════\n');

    apps.forEach((app: any) => {
      console.log(`📱 ${app.name} (${app.environment})`);
      console.log(`   ID: ${app.id}`);
      console.log(`   API Key: ${app.apiKey.substring(0, 20)}...`);
      console.log(`   Permissions: OpenAI: ${app.permissions.openai ? '✓' : '✗'}, Anthropic: ${app.permissions.anthropic ? '✓' : '✗'}`);
      console.log(`   Access Count: ${app.accessCount}`);
      console.log(`   Last Access: ${app.lastAccess || 'Never'}`);
      
      if (app.expiresAt) {
        const expired = new Date(app.expiresAt) < new Date();
        console.log(`   Status: ${expired ? '❌ EXPIRED' : '✅ Active'}`);
      }
      console.log('');
    });
  } catch (error) {
    console.error('Error reading apps config:', error);
  }
}

function revokeApp(name: string) {
  try {
    const config = JSON.parse(fs.readFileSync(APPS_CONFIG_PATH, 'utf8'));
    let found = false;

    for (const [key, app] of Object.entries(config.apps)) {
      if ((app as any).name === name) {
        delete config.apps[key];
        found = true;
        break;
      }
    }

    if (!found) {
      console.error(`❌ App "${name}" not found`);
      process.exit(1);
    }

    fs.writeFileSync(APPS_CONFIG_PATH, JSON.stringify(config, null, 2));
    console.log(`✅ App "${name}" has been revoked`);
  } catch (error) {
    console.error('Error revoking app:', error);
  }
}

function showHelp() {
  console.log(`
Key Server App Management CLI

Commands:
  register    Register a new app
  list        List all registered apps
  revoke      Revoke an app's access
  help        Show this help message

Register Options:
  --name <name>           App name (required)
  --openai                Grant OpenAI API access
  --anthropic             Grant Anthropic API access
  --ips <ip1,ip2>        Comma-separated IP whitelist
  --domains <d1,d2>      Comma-separated allowed domains
  --env <environment>     Environment: development, staging, production
  --rate-limit <n/m>      Rate limit: n requests per m minutes
  --expires <days>        Expire after n days

Examples:
  # Register a production app with both API access
  npm run manage-apps register --name "MyWebApp" --openai --anthropic --domains "myapp.com,*.myapp.com"

  # Register a development app with IP restriction
  npm run manage-apps register --name "DevApp" --openai --env development --ips "192.168.1.100" --expires 30

  # Register with custom rate limit (100 requests per 5 minutes)
  npm run manage-apps register --name "MobileApp" --anthropic --rate-limit "100/5"

  # List all apps
  npm run manage-apps list

  # Revoke an app
  npm run manage-apps revoke --name "OldApp"
`);
}

// Main execution
const { command, options } = parseArgs();

switch (command) {
  case 'register':
    registerNewApp(options);
    break;
  case 'list':
    listApps();
    break;
  case 'revoke':
    if (!options.name) {
      console.error('❌ App name required (--name <app-name>)');
      process.exit(1);
    }
    revokeApp(options.name);
    break;
  case 'help':
  default:
    showHelp();
}