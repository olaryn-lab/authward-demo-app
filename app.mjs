/**
 * Product-owned user experience reference. Authward remains the identity issuer.
 * Educational BFF: in-memory session/transaction stores are intentionally NOT
 * production ready; replace with durable distributed session storage.
 */
import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import * as oidc from 'openid-client';
import { signIn,accountPage,consentPage,errorPage,auxiliaryPage } from './ui.mjs';

const env = process.env;
const port = Number(env.PORT || 4402);
const product = env.PRODUCT_NAME || 'Demo App';
const origin = new URL(env.PRODUCT_ORIGIN || `http://127.0.0.1:${port}`);
const issuer = env.AUTHWARD_ISSUER || 'https://auth.olaryn.com';
const clientId = env.AUTHWARD_CLIENT_ID || 'authward-demo-local';
const clientSecret = env.AUTHWARD_CLIENT_SECRET || '';
const audience = env.AUTHWARD_AUDIENCE || 'https://demo.auth.olaryn.com';
const securityEnabled = origin.protocol === 'https:';
const transactions = new Map();
let configuration;

function escape(s) {
  return String(s).replace(/[&<>"']/g, x => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[x]));
}
function token() { return randomBytes(32).toString('base64url'); }
function cookie(value, maxAge = 900) {
  return `reference_session=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${securityEnabled?'; Secure':''}`;
}
function sessionId(req) {
  const raw = /(?:^|;\s*)reference_session=([^;]*)/.exec(req.headers.cookie || '')?.[1] || '';
  try { return decodeURIComponent(raw); } catch { return ''; }
}
function send(res, status, message) {
  res.writeHead(status, {'content-type':'text/html; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff'});
  res.end(message);
}

function redirect(res, url, setCookie) {
  const headers = {location: String(url), 'cache-control':'no-store'};
  if (setCookie) headers['set-cookie'] = setCookie;
  res.writeHead(303, headers);res.end();
}
function bad(res, status=400, detail='Invalid request') { send(res,status,errorPage(detail)); }
function readForm(req, limit=8000) {
  return new Promise((resolve,reject)=>{
    let data='';
    req.on('data',chunk=>{data+=chunk;if(data.length>limit){reject(new Error('Form too large'));req.destroy();}});
    req.on('end',()=>resolve(new URLSearchParams(data)));
    req.on('error',reject);
  });
}
async function config() {
  if (!clientId) throw new Error('AUTHWARD_CLIENT_ID must be set');
  if (!configuration) configuration=await oidc.discovery(new URL(issuer),clientId,clientSecret || undefined);
  return configuration;
}
function transaction(req) {
  const key=sessionId(req);const entry=transactions.get(key);
  if (!entry || entry.expires < Date.now()) { transactions.delete(key);return null; }
  return {key,entry};
}
function newTransaction(res, values={}) {
  const key=token();const entry={csrf:token(),expires:Date.now()+15*60_000,...values};
  transactions.set(key,entry);return {key,entry};
}
function confirmPost(req,res,form) {
  const state=transaction(req);
  if (!state || state.entry.csrf!==form.get('csrf')) {bad(res,403,'Form expired. Please restart this action.');return null;}
  // SameSite cookie + unguessable per-session CSRF; Origin is checked when supplied.
  if (req.headers.origin && req.headers.origin!==origin.origin) {bad(res,403,'Cross-site request refused.');return null;}
  return state;
}
function formButton(label,csrf,extra='') {return `<input type="hidden" name="csrf" value="${escape(csrf)}">${extra}<button type="submit">${escape(label)}</button>`;}
function limitString(value,max=8192) {return typeof value==='string' && value.length<=max ? value : '';}

const server=createServer(async(req,res)=>{
  const url=new URL(req.url || '/',origin);
  try {
    // One entry point: demonstrate authentication, not an invented SaaS.
    if(url.pathname==='/' && req.method==='GET') return send(res,200,signIn());
    if((url.pathname==='/demo' || url.pathname.startsWith('/demo/') ||
        url.pathname==='/app' || url.pathname.startsWith('/app/')) && req.method==='GET') {
      return redirect(res,url.pathname.startsWith('/app')?'/account':'/');
    }
    if(url.pathname==='/auth/start' && req.method==='GET') {
      if (!clientId) return bad(res,503,'Demo OAuth client ID is missing.');
      const configuration=await config();
      const verifier=oidc.randomPKCECodeVerifier();
      const challenge=await oidc.calculatePKCECodeChallenge(verifier);
      const state=oidc.randomState();const nonce=token();
      const method=url.searchParams.get('method')||'';
      if(method && !['google','github','passkey','magic'].includes(method)) return bad(res,400,'Unsupported login method');
      const {key}=newTransaction(res,{verifier,state,nonce,selectedMethod:method});
      const target=oidc.buildAuthorizationUrl(configuration,{
        redirect_uri:new URL('/callback',origin).href,response_type:'code',scope:'openid profile email',
        code_challenge:challenge,code_challenge_method:'S256',state,nonce,
        ...(audience?{resource:audience}:{}),
      });
      return redirect(res,target.href,cookie(key));
    }
    if(url.pathname==='/login' || url.pathname==='/signup') {
      const incoming=limitString(url.searchParams.get('interaction_query'));
      const stored=transaction(req);
      if(incoming && (!clientId || new URLSearchParams(incoming).get('client_id')!==clientId)) return bad(res,400,'Wrong OAuth client');
      // This is the first product-owned landing page after Authward redirects
      // here; it must be able to establish its own fresh first-party session.
      // The opaque signed envelope is authenticated by Authward at continuation,
      // never trusted here to grant access or identify a user.
      let state=stored;
      if(incoming) {
        state=stored || newTransaction(res);
        if(!stored) res.setHeader('Set-Cookie',cookie(state.key));
        state.entry.interactionQuery=incoming;
      }
      if(!state?.entry.interactionQuery) return send(res,200,signIn({mode:url.pathname==='/signup'?'signup':'login'}));
      // The visitor already picked a provider before OAuth authorization.
      // Authward's redirect back supplies the signed interaction envelope;
      // resume that choice directly rather than forcing a second click.
      const method=state.entry.selectedMethod;
      if(method && ['google','github','passkey'].includes(method)) {
        delete state.entry.selectedMethod;
        const target=new URL('/interaction/login',issuer);
        target.searchParams.set('interaction_query_b64',Buffer.from(incoming).toString('base64url'));
        target.searchParams.set('action',method==='passkey'?'passkey':'social');
        if(method!=='passkey') target.searchParams.set('provider',method);
        return redirect(res,target.href);
      }
      return send(res,200,signIn({mode:url.pathname==='/signup'?'signup':'login',interactive:true,csrf:state.entry.csrf,info:url.searchParams.get('sent')==='1'?'Check your email for the sign-in link.':''}));
    }
    if(url.pathname==='/auth/method' && req.method==='POST') {
      const form=await readForm(req),state=confirmPost(req,res,form);if(!state)return;
      const raw=state.entry.interactionQuery;
      if(!raw) return bad(res,400,'OAuth interaction missing');
      const method=form.get('method');
      const target=new URL('/interaction/login',issuer);
      target.searchParams.set('interaction_query_b64',Buffer.from(raw).toString('base64url'));
      if(method==='google' || method==='github'){target.searchParams.set('action','social');target.searchParams.set('provider',method);}
      else if(method==='passkey')target.searchParams.set('action','passkey');
      else if(method==='magic'){
        const email=limitString(form.get('email'),254).trim();
        if(!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email))return bad(res,400,'Enter a valid email address');
        target.searchParams.set('action','magic');target.searchParams.set('email',email);
      } else return bad(res,400,'Unsupported login method');
      return redirect(res,target.href);
    }
    if(url.pathname==='/callback' && req.method==='GET') {
      const flow=transaction(req);if(!flow?.entry.verifier)return bad(res,403,'Login session expired');
      const cfg=await config();
      const tokens=await oidc.authorizationCodeGrant(cfg,url,{
        pkceCodeVerifier:flow.entry.verifier,expectedState:flow.entry.state,expectedNonce:flow.entry.nonce,
      });
      const claims=tokens.claims();
      if(!claims || typeof claims.sub!=='string' || !claims.sub) return bad(res,403,'Identity could not be verified');
      // Only a verified authorization-code exchange establishes an account.
      flow.entry.account={sub:claims.sub,
        name:typeof claims.name==='string'?claims.name:'',
        email:typeof claims.email==='string'?claims.email:'',
      };
      flow.entry.accessToken=tokens.access_token;
      flow.entry.refreshToken=tokens.refresh_token;
      delete flow.entry.verifier; delete flow.entry.nonce; delete flow.entry.interactionQuery;
      return redirect(res,'/account');
    }
    if(url.pathname==='/account') {
      const state=transaction(req);
      if(!state?.entry.account) return redirect(res,'/login');
      return send(res,200,accountPage(state.entry.account,state.entry.csrf));
    }
    if(url.pathname==='/logout' && req.method==='POST') {
      const form=await readForm(req),flow=confirmPost(req,res,form);if(!flow)return;
      transactions.delete(flow.key);
      // Demonstration clears the product session only. Production also revokes
      // Authward refresh credentials and implements issuer end-session logout.
      return redirect(res,'/login',cookie('',0));
    }
    if(url.pathname==='/consent' && req.method==='GET') {
      const raw=limitString(url.searchParams.get('interaction_query'));
      const confirmation=limitString(url.searchParams.get('confirmation'),2048);
      if(!raw || !confirmation || new URLSearchParams(raw).get('client_id')!==clientId) return bad(res);
      const old=transaction(req);const created=old || newTransaction(res);
      if(!old)res.setHeader('Set-Cookie',cookie(created.key));
      created.entry.consent={raw,confirmation};
      const scopes=(new URLSearchParams(raw).get('scope')||'').split(/\s+/).filter(Boolean);
      return send(res,200,consentPage({csrf:created.entry.csrf,scopes}));
    }
    if(url.pathname==='/auth/consent' && req.method==='POST') {
      const form=await readForm(req),flow=confirmPost(req,res,form);if(!flow)return;
      const {raw,confirmation}=flow.entry.consent || {};
      if(!raw || !confirmation || !['allow','deny'].includes(form.get('decision')))return bad(res);
      const target=new URL('/interaction/consent',issuer);
      target.searchParams.set('interaction_query_b64',Buffer.from(raw).toString('base64url'));
      target.searchParams.set('confirmation',confirmation);target.searchParams.set('decision',form.get('decision'));
      return redirect(res,target.href);
    }
    if(url.pathname==='/device' && req.method==='GET') {
      const code=limitString(url.searchParams.get('user_code'),128);
      const confirmation=limitString(url.searchParams.get('confirmation'),2048);
      const old=transaction(req),created=old || newTransaction(res);
      if(!old)res.setHeader('Set-Cookie',cookie(created.key));
      if(code && confirmation)created.entry.device={code,confirmation};
      const pending=created.entry.device;
      if(!pending) return send(res,200,auxiliaryPage('Connect device',`<h1>Connect your ${escape(product)} device</h1><form method="get" action="/device/start"><input name="user_code" placeholder="Device code" required><button>Continue</button></form>`));
      return send(res,200,auxiliaryPage('Approve device',`<h1>Authorize this device?</h1><p>Device code: ${escape(pending.code)}</p><form action="/auth/device" method="post"><input type="hidden" name="decision" value="approve">${formButton('Approve',created.entry.csrf)}</form><form action="/auth/device" method="post"><input type="hidden" name="decision" value="deny">${formButton('Deny',created.entry.csrf)}</form>`));
    }
    if(url.pathname==='/device/start' && req.method==='GET') {
      const code=limitString(url.searchParams.get('user_code'),128);
      if(!code) return bad(res);
      const target=new URL('/interaction/device/prepare',issuer);target.searchParams.set('user_code',code);
      return redirect(res,target.href);
    }
    if(url.pathname==='/auth/device' && req.method==='POST') {
      const form=await readForm(req),flow=confirmPost(req,res,form);if(!flow)return;
      const {code,confirmation}=flow.entry.device || {};
      if(!code || !confirmation || !['approve','deny'].includes(form.get('decision')))return bad(res);
      const target=new URL('/interaction/device',issuer);
      target.searchParams.set('user_code',code);target.searchParams.set('confirmation',confirmation);
      target.searchParams.set('decision',form.get('decision'));
      return redirect(res,target.href);
    }
    return bad(res,404,'Page not found');
  } catch (error) {
    console.error('Reference app error:',error instanceof Error ? error.name : 'unknown');
    return bad(res,500,'Something went wrong. Please try again.');
  }
});
if (process.env.NODE_ENV !== 'test') server.listen(port,'127.0.0.1',()=>console.log(`${product} reference running on ${origin.origin}`));
export { server };
