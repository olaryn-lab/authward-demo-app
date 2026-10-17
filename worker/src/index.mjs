/**
 * Cloudflare Workers relying party for the public Authward demo.
 * Customer-facing HTML remains the demo's own UI. Production Authward owns
 * Google/GitHub OAuth, email magic links, passkeys, identity and tokens.
 * No OAuth client secret is needed: authorization-code + PKCE S256.
 * Encrypted, short-lived, host-only cookies work across all edge isolates.
 */
import * as oidc from 'openid-client';
import { signIn, accountPage, consentPage, errorPage } from '../../ui.mjs';

const cookieName = '__Host-authward_demo';
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const audience = 'https://demo-hosted.auth.olaryn.com';
const defaultIssuer = 'https://auth.olaryn.com';
const lifetimeSeconds = 15 * 60;
const memory = new Map();

function b64url(bytes) {
  let value = '';
  for (const byte of bytes) value += String.fromCharCode(byte);
  return btoa(value).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
function from64url(value) {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw Error('Invalid encrypted cookie');
  const raw = atob(value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4));
  return Uint8Array.from(raw, char => char.charCodeAt(0));
}
const random = () => b64url(crypto.getRandomValues(new Uint8Array(32)));

async function cookieKey(env) {
  const value = env.SESSION_KEY;
  if (typeof value !== 'string' || value.length < 43) throw Error('Missing secure SESSION_KEY');
  const keyBytes = from64url(value);
  if (keyBytes.length !== 32) throw Error('SESSION_KEY must be 32 random bytes');
  if (!memory.has(value)) memory.set(value, await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt', 'decrypt']));
  return memory.get(value);
}
async function seal(data, env) {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const bytes = encoder.encode(JSON.stringify(data));
  const encrypted = new Uint8Array(await crypto.subtle.encrypt({name: 'AES-GCM', iv: nonce}, await cookieKey(env), bytes));
  const out = new Uint8Array(nonce.length + encrypted.length);
  out.set(nonce, 0); out.set(encrypted, nonce.length);
  return b64url(out);
}
async function unseal(value, env) {
  if (!value || value.length > 3900) return null;
  try {
    const raw = from64url(value);
    if (raw.length < 29) return null;
    const decrypted = await crypto.subtle.decrypt({name: 'AES-GCM', iv: raw.slice(0, 12)}, await cookieKey(env), raw.slice(12));
    const session = JSON.parse(decoder.decode(decrypted));
    if (session.v !== 1 || !Number.isFinite(session.exp) || session.exp <= Date.now()) return null;
    return session;
  } catch { return null; }
}
async function readSession(req, env) {
  const cookie = (req.headers.get('cookie') || '').split(';').map(s => s.trim()).find(s => s.startsWith(`${cookieName}=`));
  return unseal(cookie?.slice(cookieName.length + 1), env);
}
function setCookie(value, maxAge=lifetimeSeconds) {
  return `${cookieName}=${value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${maxAge}`;
}
function headers(extra={}) {
  return {'cache-control': 'private, no-store',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'strict-origin-when-cross-origin',
    'content-security-policy': "default-src 'none'; base-uri 'none'; form-action 'self' https://auth.olaryn.com; frame-ancestors 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'self' data:",
    ...extra};
}
const html = (body, status=200, extra={}) => new Response(body,{status,headers:headers({'content-type':'text/html; charset=utf-8',...extra})});
const redirect = (url, cookie) => new Response(null,{status:303,headers:headers({'location':url,...(cookie?{'set-cookie':cookie}:{})})});
const errorHtml = (message, status=400) => html(errorPage(message), status);
function publicOrigin(env) {
  const origin = new URL(env.PUBLIC_ORIGIN || '');
  if(origin.protocol !== 'https:' || origin.origin!==origin.href.replace(/\/$/, '') || origin.username || origin.password || origin.search || origin.hash) throw Error('PUBLIC_ORIGIN must be an HTTPS origin');
  return origin;
}
function configured(env) {
  if (!env.SESSION_KEY) throw Error('SESSION_KEY is not configured');
  const origin = publicOrigin(env);
  return {origin, issuer:env.AUTHWARD_ISSUER||defaultIssuer,
    clientId:env.AUTHWARD_CLIENT_ID||'authward-demo-hosted',
    audience:env.AUTHWARD_AUDIENCE||audience};
}
function sameOrigin(req, origin) {
  return req.headers.get('origin') === origin || (!req.headers.has('origin') && req.headers.get('sec-fetch-site') === 'same-origin');
}
async function formData(req) {
  const type=req.headers.get('content-type')||'';
  if(!type.startsWith('application/x-www-form-urlencoded'))throw Error('Unexpected content type');
  const body=await req.text();
  if(body.length>4096)throw Error('Form too large');
  return new URLSearchParams(body);
}
function validEmail(email) { return typeof email === 'string' && email.length <= 254 && /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email); }

export function createWorker(client=oidc) {
  const discoveryCache = new Map();
  async function oidcConfig(c) {
    const key=`${c.issuer}|${c.clientId}`;
    if(!discoveryCache.has(key))discoveryCache.set(key, client.discovery(new URL(c.issuer), c.clientId).catch(e=>{discoveryCache.delete(key);throw e;}));
    return discoveryCache.get(key);
  }
  async function start(req,c,env,method,email='') {
    if(!['','google','github','passkey','magic'].includes(method))return errorHtml('Unsupported login method');
    if(method==='magic'&&!validEmail(email))return errorHtml('Enter a valid email address');
    const codeVerifier=client.randomPKCECodeVerifier();
    const state=client.randomState();
    const nonce=random();
    const params={redirect_uri:new URL('/callback',c.origin).href,
      response_type:'code',scope:'openid profile email',resource:c.audience,
      code_challenge:await client.calculatePKCECodeChallenge(codeVerifier),code_challenge_method:'S256',state,nonce};
    if(['google','github'].includes(method))params.upstream_provider=method;
    if(method==='passkey')params.auth_method='passkey';
    if(method==='magic'){
      params.auth_method='magic_link'; params.login_hint=email;
      params.return_to=new URL('/login?sent=1', c.origin).href;
    }
    const cfg=await oidcConfig(c);
    const url=client.buildAuthorizationUrl(cfg,params);
    const session={v:1,exp:Date.now()+lifetimeSeconds*1000,csrf:random(),pkceCodeVerifier:codeVerifier,state,nonce};
    return redirect(url.href,setCookie(await seal(session,env)));
  }
  return {async fetch(req,env) {
    const u=new URL(req.url);
    if(u.pathname==='/healthz'){
      try { configured(env); await cookieKey(env); }
      catch { return new Response('demo not configured',{status:503,headers:headers({'content-type':'text/plain'})}); }
      return new Response('ok',{headers:headers({'content-type':'text/plain'})});
    }
    let c;
    try {c=configured(env);}catch {return new Response('Demo hosting is not configured',{status:503,headers:headers()});}
    if(u.origin!==c.origin.origin)return new Response('Host mismatch',{status:421,headers:headers()});
    const current=await readSession(req,env);
    try {
      if(req.method==='GET' && ['/', '/login', '/signup'].includes(u.pathname)) {
        if(current?.account)return redirect('/account');
        const session=current||{v:1,exp:Date.now()+lifetimeSeconds*1000,csrf:random()};
        return html(signIn({mode:u.pathname==='/signup'?'signup':'login',csrf:session.csrf,
          info:u.searchParams.get('sent')==='1'?'Check your email for a sign-in link.':''}),200,
          current?{}:{'set-cookie':setCookie(await seal(session,env))});
      }
      if(req.method==='GET' && u.pathname==='/auth/start') {
        const method=u.searchParams.get('method')||'';
        return start(req,c,env,method);
      }
      if(req.method==='POST' && u.pathname==='/auth/email') {
        if(!current || !sameOrigin(req,c.origin.origin))return errorHtml('Invalid sign-in request',403);
        const form=await formData(req);
        if(form.get('csrf')!==current.csrf)return errorHtml('Sign-in form expired',403);
        return start(req,c,env,'magic',(form.get('email')||'').trim());
      }
      if(req.method==='GET' && u.pathname==='/callback') {
        if(!current?.pkceCodeVerifier || !current.state || !current.nonce)return errorHtml('Sign-in session expired',403);
        const cfg=await oidcConfig(c);
        const tokens=await client.authorizationCodeGrant(cfg,u,{
          pkceCodeVerifier:current.pkceCodeVerifier,expectedState:current.state,expectedNonce:current.nonce});
        const claims=tokens.claims?.();
        if(!claims || typeof claims.sub!=='string' || !claims.sub)return errorHtml('No verified identity was returned',403);
        // OIDC intentionally doesn't promise profile/email in ID tokens. The
        // userinfo endpoint serves the scopes granted to this OAuth client.
        // openid-client binds its response to the verified ID-token `sub`.
        let identity=claims;
        if((!claims.email || !claims.name) && typeof tokens.access_token==='string') {
          const profile=await client.fetchUserInfo(cfg,tokens.access_token,claims.sub);
          if(profile.sub!==claims.sub)throw Error('UserInfo subject mismatch');
          identity={...profile,...Object.fromEntries(Object.entries(claims).filter(([_,value])=>value!=null))};
        }
        const session={v:1,exp:Date.now()+lifetimeSeconds*1000,csrf:random(),
          account:{sub:claims.sub,name:typeof identity.name==='string'?identity.name:'',email:typeof identity.email==='string'?identity.email:''},
          // RP-initiated logout needs the ID token to bind the provider
          // session to this relying party. Kept only in the encrypted,
          // HttpOnly cookie, never HTML, logs, or a persistent database.
          ...(typeof tokens.id_token==='string' && tokens.id_token.length<=2200
            ? {idTokenHint:tokens.id_token} : {})};
        return redirect('/account',setCookie(await seal(session,env)));
      }
      if(req.method==='GET' && u.pathname==='/account'){
        if(!current?.account)return redirect('/login');
        return html(accountPage(current.account,current.csrf));
      }
      if(req.method==='POST' && u.pathname==='/logout'){
        if(!current?.account||!sameOrigin(req,c.origin.origin))return errorHtml('Invalid logout request',403);
        const form=await formData(req);
        if(current.csrf!==form.get('csrf'))return errorHtml('Invalid logout request',403);
        // Clearing only this application's cookie leaves the Authward SSO
        // session active, so the next sign-in silently authenticates. Use
        // the provider's standard RP-initiated logout endpoint instead.
        // Authward validates the id_token_hint and the exact registered
        // post-logout redirect, terminates the central browser session, and
        // navigates back to the demo's own login page. In the rare event
        // that an ID token exceeded the cookie budget, Authward asks the
        // user to confirm logout rather than silently leaving them signed in.
        const cfg=await oidcConfig(c);
        const params={post_logout_redirect_uri:new URL('/',c.origin).href,
          ...(current.idTokenHint?{id_token_hint:current.idTokenHint}:{})};
        const target=client.buildEndSessionUrl(cfg,params);
        return redirect(target.href,setCookie('',0));
      }
      if(req.method==='GET' && u.pathname==='/consent'){
        const raw=u.searchParams.get('interaction_query')||'';
        const confirmation=u.searchParams.get('confirmation')||'';
        if(raw.length>8192||!raw||!confirmation||confirmation.length>2048||new URLSearchParams(raw).get('client_id')!==c.clientId)
          return errorHtml('Invalid consent request');
        const session={...(current||{}),v:1,exp:Date.now()+lifetimeSeconds*1000,csrf:current?.csrf||random(),
          pendingConsent:{raw,confirmation}};
        return html(consentPage({csrf:session.csrf,scopes:(new URLSearchParams(raw).get('scope')||'').split(/\s+/).filter(Boolean)}),200,
          {'set-cookie':setCookie(await seal(session,env))});
      }
      if(req.method==='POST' && u.pathname==='/auth/consent'){
        if(!current?.pendingConsent||!sameOrigin(req,c.origin.origin))return errorHtml('Invalid consent request',403);
        const form=await formData(req);
        if(form.get('csrf')!==current.csrf||!['allow','deny'].includes(form.get('decision')))
          return errorHtml('Invalid consent decision',403);
        const target=new URL('/interaction/consent',c.issuer);
        target.searchParams.set('interaction_query_b64',b64url(encoder.encode(current.pendingConsent.raw)));
        target.searchParams.set('confirmation',current.pendingConsent.confirmation);
        target.searchParams.set('decision',form.get('decision'));
        // Preserve OAuth state + PKCE across consent. Clearing this cookie
        // discards the pending authorization and makes the callback fail, even
        // though the user approved successfully. Remove only consent metadata;
        // Authward's signed one-time confirmation prevents decision replay.
        const {pendingConsent:_consumed,...ongoing}=current;
        return redirect(target.href,setCookie(await seal(ongoing,env)));
      }
      return errorHtml('Page not found',404);
    } catch (e) {
      console.error('Demo Worker failed:',e instanceof Error?e.name:'UnexpectedError');
      return errorHtml('Could not complete the authentication request',502);
    }
  }};
}
export default createWorker();
