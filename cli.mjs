#!/usr/bin/env node
/** Minimal RFC 8628 device-code login, no credentials stored or printed. */
import { fileURLToPath } from 'node:url';
import * as oidc from 'openid-client';

export const issuer = process.env.AUTHWARD_ISSUER || 'https://auth.olaryn.com';
export const clientId = process.env.AUTHWARD_DEMO_CLI_ID || 'authward-demo-cli';
export const audience = process.env.AUTHWARD_AUDIENCE || 'https://demo.auth.olaryn.com';

export function publicDeviceInstructions(device) {
  if (!device || typeof device.verification_uri !== 'string' || typeof device.user_code !== 'string')
    throw new Error('Invalid Authward device authorization response');
  const target = new URL(device.verification_uri);
  if (!['http:', 'https:'].includes(target.protocol)) throw new Error('Invalid verification URL');
  return `Open: ${target.origin}${target.pathname}\nCode: ${device.user_code}\nWaiting for approval...`;
}

export function publicIdentity(tokens) {
  const claims = tokens.claims?.();
  if (!claims || typeof claims.sub !== 'string' || !claims.sub) throw new Error('OIDC identity was not verified');
  return { subject: claims.sub,
    ...(typeof claims.email === 'string' ? {email: claims.email} : {}),
    ...(typeof claims.name === 'string' ? {name: claims.name} : {}),
  };
}

export async function login({ client = oidc, output = console.log } = {}) {
  const config = await client.discovery(new URL(issuer), clientId);
  const device = await client.initiateDeviceAuthorization(config, {
    scope: 'openid profile email', resource: audience,
  });
  output(publicDeviceInstructions(device));
  // The official library handles authorization_pending, slow_down, polling
  // interval and expiry. Raw access/refresh/ID tokens never reach output.
  const tokens = await client.pollDeviceAuthorizationGrant(config, device);
  const identity = publicIdentity(tokens);
  output(`Signed in through Authward\n${JSON.stringify(identity, null, 2)}`);
  return identity;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const arg = process.argv[2];
  if (arg === 'login') {
    try { await login(); }
    catch (error) {
      // Never print response bodies, device tokens, callback URLs or query strings.
      console.error('Authward login did not complete. Check the demo server, authorization and device-code expiry.');
      process.exitCode = 1;
    }
  } else {
    console.log('Usage: node cli.mjs login');
    if(arg)process.exitCode=2;
  }
}
