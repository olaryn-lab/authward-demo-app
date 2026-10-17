/**
 * Minimal OIDC relying party for the production Authward identity service.
 * This demo does NOT implement sign-in, Google, GitHub, magic links, passkeys,
 * consent or device approvals; those are hosted and implemented by Authward.
 * Process-local sessions are educational only; not production middleware.
 */
import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import * as oidc from 'openid-client';
import { signIn, accountPage, consentPage, errorPage } from './ui.mjs';

const issuer = process.env.AUTHWARD_ISSUER || 'https://auth.olaryn.com';
const clientId = process.env.AUTHWARD_CLIENT_ID || 'authward-demo-local';
const audience = process.env.AUTHWARD_AUDIENCE || 'https://demo.auth.olaryn.com';
const port = Number(process.env.PORT || 4402);
const publicOrigin = new URL(process.env.PRODUCT_ORIGIN || `http://127.0.0.1:${port}`);
const cookieName = 'authward_demo_session';
const sessions = new Map();
let configuration;

function createSession({account=null}={}) {
  const key=randomBytes(32).toString('base64url');
  const entry={expiresAt:Date.now()+15*60_000,csrf:randomBytes(32).toString('base64url'),...(account?{account}:{})};
  sessions.set(key,entry);return {key,...entry};
}
function validEmail(value) {return typeof value==='string' && value.length<=254 && /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(value);}
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
function htmlWithCookie(res,status,body,cookie){
  const headers={'content-type':'text/html; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff'};
  if(cookie)headers['set-cookie']=cookie;
  res.writeHead(status,headers);res.end(body);
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

async function startAuthorization(res, mode, email='') {
  const allowed = new Set(['google','github','passkey','magic','']);
  if(!allowed.has(mode))throw Error('Unsupported authentication method');
  const cfg=await oidcConfig();
  const flow=createSession();
  flow.pkceCodeVerifier=oidc.randomPKCECodeVerifier();
  const challenge=await oidc.calculatePKCECodeChallenge(flow.pkceCodeVerifier);
  flow.state=oidc.randomState();
  flow.nonce=randomBytes(32).toString('base64url');
  sessions.set(flow.key,flow);
  const request={
    redirect_uri:new URL('/callback',publicOrigin).href,
    response_type:'code',scope:'openid profile email',
    code_challenge:challenge,code_challenge_method:'S256',
    state:flow.state,nonce:flow.nonce,resource:audience,
  };
  if(mode==='google'||mode==='github')request.upstream_provider=mode;
  if(mode==='passkey')request.auth_method='passkey';
  if(mode==='magic') {
    if(!validEmail(email))throw Error('Invalid email address');
    request.auth_method='magic_link';
    request.login_hint=email;
    request.return_to=new URL('/login?sent=1',publicOrigin).href;
  }
  const target=oidc.buildAuthorizationUrl(cfg,request);
  return redirect(res,target.href,sessionCookie(flow.key));
}

export const server = createServer(async (req, res) => {
  const url = new URL(req.url || '/', publicOrigin);
  try {
    if (['/', '/login', '/signup'].includes(url.pathname) && req.method === 'GET') {
      const current=session(req);
      if(current?.account)return redirect(res,'/account');
      const flow=current || createSession();
      return htmlWithCookie(res,200,signIn({mode:url.pathname==='/signup'?'signup':'login',
        csrf:flow.csrf,info:url.searchParams.get('sent')==='1'?'Check your email for a sign-in link.':''}),
        current?null:sessionCookie(flow.key));
    }
    if(url.pathname==='/auth/start' && req.method==='GET') {
      const method=url.searchParams.get('method')||'';
      if(!['','google','github','passkey'].includes(method))return html(res,400,errorPage('Choose a supported sign-in method.'));
      return startAuthorization(res,method);
    }
    if(url.pathname==='/auth/email' && req.method==='POST') {
      const current=session(req);
      const form=await readForm(req);
      if(!current||!sameOriginPost(req)||form.get('csrf')!==current.csrf)
        return html(res,403,errorPage('Sign-in form expired. Please try again.'));
      const email=(form.get('email')||'').trim();
      if(!validEmail(email))return html(res,400,errorPage('Please enter a valid email address.'));
      return startAuthorization(res,'magic',email);
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
      // The email/profile scopes may be returned from UserInfo rather than
      // repeated in the ID token. Bind the response to the verified subject.
      let identity = claims;
      if ((!claims.email || !claims.name) && typeof tokens.access_token === 'string') {
        const profile = await oidc.fetchUserInfo(cfg, tokens.access_token, claims.sub);
        if (profile.sub !== claims.sub) throw Error('UserInfo subject mismatch');
        identity = {...profile,...Object.fromEntries(Object.entries(claims).filter(([,value])=>value!=null))};
      }
      const account = {
        sub: claims.sub,
        name: typeof identity.name === 'string' ? identity.name : '',
        email: typeof identity.email === 'string' ? identity.email : '',
      };
      const key = randomBytes(32).toString('base64url');
      sessions.delete(current.key);
      sessions.set(key, { expiresAt: Date.now()+15*60_000, account,
        csrf: randomBytes(32).toString('base64url'),
        // Server-side only: never print ID tokens or expose them in HTML.
        idTokenHint: typeof tokens.id_token==='string'?tokens.id_token:undefined });
      return redirect(res, '/account', sessionCookie(key));
    }
    if(url.pathname==='/consent' && req.method==='GET') {
      const raw=url.searchParams.get('interaction_query')||'';
      const confirmation=url.searchParams.get('confirmation')||'';
      if(!raw||raw.length>8192||!confirmation||confirmation.length>2048||
         new URLSearchParams(raw).get('client_id')!==clientId)
        return html(res,400,errorPage('Invalid consent request.'));
      const existing=session(req),flow=existing||createSession();
      flow.pendingConsent={raw,confirmation};sessions.set(flow.key,flow);
      const scopes=(new URLSearchParams(raw).get('scope')||'').split(/\s+/).filter(Boolean);
      return htmlWithCookie(res,200,consentPage({csrf:flow.csrf,scopes}),existing?null:sessionCookie(flow.key));
    }
    if(url.pathname==='/auth/consent' && req.method==='POST') {
      const current=session(req),form=await readForm(req);
      if(!current?.pendingConsent||!sameOriginPost(req)||form.get('csrf')!==current.csrf||
        !['allow','deny'].includes(form.get('decision')))
        return html(res,403,errorPage('Approval expired or invalid.'));
      const {raw,confirmation}=current.pendingConsent;
      delete sessions.get(current.key).pendingConsent;
      const target=new URL('/interaction/consent',issuer);
      target.searchParams.set('interaction_query_b64',Buffer.from(raw).toString('base64url'));
      target.searchParams.set('confirmation',confirmation);
      target.searchParams.set('decision',form.get('decision'));
      return redirect(res,target.href);
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
      const cfg = await oidcConfig();
      const target=oidc.buildEndSessionUrl(cfg,{
        post_logout_redirect_uri:new URL('/',publicOrigin).href,
        ...(current.idTokenHint?{id_token_hint:current.idTokenHint}:{})
      });
      sessions.delete(current.key);
      return redirect(res, target.href, sessionCookie('', 0));
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
