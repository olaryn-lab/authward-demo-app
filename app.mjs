/**
 * Minimal OIDC relying party for the production Authward identity service.
 * This demo does NOT implement sign-in, Google, GitHub, magic links, passkeys,
 * consent or device approvals; those are hosted and implemented by Authward.
 * Process-local sessions are educational only; not production middleware.
 */
import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import * as oidc from 'openid-client';
import { accountPage, errorPage } from './ui.mjs';

const issuer = process.env.AUTHWARD_ISSUER || 'https://auth.olaryn.com';
const clientId = process.env.AUTHWARD_CLIENT_ID || 'authward-demo-local';
const audience = process.env.AUTHWARD_AUDIENCE || 'https://demo.auth.olaryn.com';
const port = Number(process.env.PORT || 4402);
const publicOrigin = new URL(process.env.PRODUCT_ORIGIN || `http://127.0.0.1:${port}`);
const cookieName = 'authward_demo_session';
const sessions = new Map();
let configuration;

function session(req) {
  const raw = /(?:^|;\s*)authward_demo_session=([^;]*)/.exec(req.headers.cookie || '')?.[1];
  const value = raw ? sessions.get(raw) : null;
  if (!value) return null;
  if (value.expiresAt <= Date.now()) { sessions.delete(raw); return null; }
  return { key: raw, ...value };
}
function sessionCookie(id, ageSeconds = 900) {
  return `${cookieName}=${id}; HttpOnly; Path=/; SameSite=Lax; Max-Age=${ageSeconds}${publicOrigin.protocol === 'https:' ? '; Secure' : ''}`;
}
function redirect(res, destination, cookie) {
  const headers = { location: destination, 'cache-control': 'no-store' };
  if (cookie) headers['set-cookie'] = cookie;
  res.writeHead(303, headers); res.end();
}
function html(res, status, body) {
  res.writeHead(status, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options':'nosniff' });
  res.end(body);
}
async function oidcConfig() {
  if (!configuration) configuration = await oidc.discovery(new URL(issuer), clientId);
  return configuration;
}
function sameOriginPost(req) {
  const candidate = req.headers.origin;
  if (candidate) return candidate === publicOrigin.origin;
  return req.headers['sec-fetch-site'] === 'same-origin';
}
async function readForm(req) {
  let body = '';
  for await (const part of req) {
    body += part;
    if (body.length > 4096) throw Error('Form too large');
  }
  return new URLSearchParams(body);
}

export const server = createServer(async (req, res) => {
  const url = new URL(req.url || '/', publicOrigin);
  try {
    if (['/', '/login', '/signup'].includes(url.pathname) && req.method === 'GET') {
      if (session(req)?.account) return redirect(res, '/account');
      return redirect(res, '/auth/start');
    }
    if (url.pathname === '/auth/start' && req.method === 'GET') {
      const cfg = await oidcConfig();
      const key = randomBytes(32).toString('base64url');
      const pkceCodeVerifier = oidc.randomPKCECodeVerifier();
      const codeChallenge = await oidc.calculatePKCECodeChallenge(pkceCodeVerifier);
      const state = oidc.randomState();
      const nonce = randomBytes(32).toString('base64url');
      sessions.set(key, { expiresAt: Date.now()+15*60_000, state, nonce, pkceCodeVerifier });
      const authUrl = oidc.buildAuthorizationUrl(cfg, {
        redirect_uri: new URL('/callback', publicOrigin).href,
        response_type: 'code', scope: 'openid profile email',
        code_challenge: codeChallenge, code_challenge_method: 'S256', state, nonce,
        resource: audience,
      });
      return redirect(res, authUrl.href, sessionCookie(key));
    }
    if (url.pathname === '/callback' && req.method === 'GET') {
      const current = session(req);
      if (!current?.pkceCodeVerifier) return html(res, 403, errorPage('Sign-in session expired. Start again.'));
      const cfg = await oidcConfig();
      // openid-client validates the authorization response, issuer, state,
      // nonce and code exchange. We do not parse OAuth tokens ourselves.
      const tokens = await oidc.authorizationCodeGrant(cfg, url, {
        pkceCodeVerifier: current.pkceCodeVerifier,
        expectedState: current.state, expectedNonce: current.nonce,
      });
      const claims = tokens.claims();
      if (!claims || typeof claims.sub !== 'string' || !claims.sub) {
        return html(res, 403, errorPage('Authward did not return a verified identity.'));
      }
      const account = {
        sub: claims.sub,
        name: typeof claims.name === 'string' ? claims.name : '',
        email: typeof claims.email === 'string' ? claims.email : '',
      };
      const key = randomBytes(32).toString('base64url');
      sessions.delete(current.key);
      sessions.set(key, { expiresAt: Date.now()+15*60_000, account,
        csrf: randomBytes(32).toString('base64url') });
      return redirect(res, '/account', sessionCookie(key));
    }
    if (url.pathname === '/account' && req.method === 'GET') {
      const current = session(req);
      if (!current?.account) return redirect(res, '/auth/start');
      return html(res, 200, accountPage(current.account, current.csrf));
    }
    if (url.pathname === '/logout' && req.method === 'POST') {
      const form = await readForm(req);
      const current = session(req);
      if (!current?.account || !sameOriginPost(req) || form.get('csrf') !== current.csrf) {
        return html(res, 403, errorPage('Logout request expired or invalid.'));
      }
      sessions.delete(current.key);
      return redirect(res, '/', sessionCookie('', 0));
    }
    return html(res, 404, errorPage('Page not found.'));
  } catch (error) {
    // Never log authorization code, state, raw URL, token, or provider error.
    console.error('Authward demo OIDC flow failed:', error instanceof Error ? error.name : 'unknown_error');
    return html(res, 502, errorPage('Sign-in could not be completed. Try again.'));
  }
});

if (process.env.NODE_ENV !== 'test') server.listen(port, '127.0.0.1', () => {
  console.log(`Authward OIDC demo listening on ${publicOrigin.origin}`);
});
