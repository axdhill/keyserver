/**
 * Client-side decryption utility for browser environments
 * This file can be copied to your client application
 */

export async function decryptApiKey(
  encryptedData: string,
  secret: string
): Promise<string> {
  const { encrypted, salt, iv, authTag } = JSON.parse(encryptedData);
  
  // Convert hex strings to buffers
  const saltBuffer = hexToBuffer(salt);
  const ivBuffer = hexToBuffer(iv);
  const authTagBuffer = hexToBuffer(authTag);
  const encryptedBuffer = hexToBuffer(encrypted);
  
  // Import the secret as key material
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  
  // Derive the actual encryption key
  const key = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: saltBuffer,
      iterations: 100000,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );
  
  // Combine encrypted data with auth tag
  const ciphertext = new Uint8Array(encryptedBuffer.byteLength + authTagBuffer.byteLength);
  ciphertext.set(new Uint8Array(encryptedBuffer), 0);
  ciphertext.set(new Uint8Array(authTagBuffer), encryptedBuffer.byteLength);
  
  // Decrypt
  const decryptedBuffer = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: ivBuffer
    },
    key,
    ciphertext
  );
  
  // Convert back to string
  const decoder = new TextDecoder();
  return decoder.decode(decryptedBuffer);
}

function hexToBuffer(hex: string): ArrayBuffer {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes.buffer;
}

/**
 * Example usage:
 * 
 * async function fetchAndDecryptKey() {
 *   const response = await fetch('https://your-server.railway.app/api/keys/openai', {
 *     headers: {
 *       'X-API-Key': 'ks_your_api_key_here'
 *     }
 *   });
 *   
 *   const data = await response.json();
 *   const apiKey = await decryptApiKey(data.encryptedKey, 'ks_your_api_key_here');
 *   
 *   // Use the decrypted API key
 *   console.log('Decrypted key prefix:', apiKey.substring(0, 8) + '...');
 *   return apiKey;
 * }
 */