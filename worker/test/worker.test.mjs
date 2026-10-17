import {test} from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {createWorker} from '../src/index.mjs';

const origin='https://authward-demo.example.test';
const config={PUBLIC_ORIGIN:origin,SESSION_KEY:randomBytes(32).toString('base64url'),AUTHWARD_CLIENT_ID:'authward-demo-hosted'};
function stub() {
 const calls=[];
 const client={
   async discovery(url,id){calls.push({action:'discovery',issuer:String(url),id});return {fixture:true};},
   randomPKCECodeVerifier(){return 'pkce-verifier';},
   randomState(){return 'state-value';},
   async calculatePKCECodeChallenge(verifier){assert.equal(verifier,'pkce-verifier');return 'challenge-value';},
   buildAuthorizationUrl(_cfg,params){calls.push({action:'authorize',params});return new URL('https://auth.olaryn.com/api/auth/oauth2/authorize?response_type=code');},
   async authorizationCodeGrant(_cfg,url,options){calls.push({action:'token',url:String(url),options});return {claims:()=>({sub:'subject-42',email:'test@example.test',name:'Demo User'})};},
 };
 const worker=createWorker(client);
 const send=(path,init={},env=config)=>worker.fetch(new Request(`${origin}${path}`,init),env);
 return {worker,calls,send};
}
const cookie=(response)=>response.headers.get('set-cookie')?.split(';')[0];

const form=(data,authCookie,externalOrigin=origin)=>({method:'POST',headers:{origin:externalOrigin,cookie:authCookie,'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams(data)});

test('health is green only with valid runtime origin and encryption key',async()=>{
  const {send}=stub();
  assert.equal((await send('/healthz')).status,200);
  assert.equal((await send('/healthz',{}, {...config,SESSION_KEY:''})).status,503);
  assert.equal((await send('/healthz',{}, {...config,SESSION_KEY:'too-short'})).status,503);
  assert.equal((await send('/healthz',{}, {...config,PUBLIC_ORIGIN:''})).status,503);
});

test('hosted login is application-owned, state encrypted, and responsive',async()=>{
 const {send}=stub();
 const response=await send('/login');
 assert.equal(response.status,200);
 assert.match(response.headers.get('set-cookie'),/__Host-authward_demo=[^;]+; Path=\/; Secure; HttpOnly; SameSite=Lax/);
 const html=await response.text();
 for(const title of ['Continue with Google','Continue with GitHub','Sign in with a passkey','Send sign-in link'])assert.match(html,new RegExp(title));
 assert.match(html,/form method="post" action="\/auth\/email"/);
 assert.doesNotMatch(cookie(response),/state-value|pkce-verifier/);
});

test('exact public host is required; missing encryption secret never falls back to insecure sessions',async()=>{
 const {worker,send}=stub();
 const mismatched=await worker.fetch(new Request('https://evil.example.test/login'),config);
 assert.equal(mismatched.status,421);
 const noSecret=await send('/login',{}, {...config,SESSION_KEY:''});
 assert.equal(noSecret.status,503);
 const httpOrigin=await send('/login',{}, {...config,PUBLIC_ORIGIN:'http://127.0.0.1:8787'});
 assert.equal(httpOrigin.status,503);
});

test('Google and GitHub dispatch OIDC requests with exact redirect and PKCE',async()=>{
 for(const method of ['google','github']){
  const {send,calls}=stub();
  const response=await send(`/auth/start?method=${method}`);
  assert.equal(response.status,303);
  assert.equal(response.headers.get('location'),'https://auth.olaryn.com/api/auth/oauth2/authorize?response_type=code');
  const params=calls.find(x=>x.action==='authorize')?.params;
  assert.equal(params.redirect_uri,`${origin}/callback`);
  assert.equal(params.upstream_provider,method);
  assert.equal(params.code_challenge_method,'S256');
  assert.equal(params.code_challenge,'challenge-value');
  assert.equal(params.state,'state-value');
  assert.equal(params.resource,'https://demo.auth.olaryn.com');
 }
});

test('magic-link email submission requires same-origin encrypted session and CSRF',async()=>{
 const {send,calls}=stub();
 const landing=await send('/login');
 const csrf=(await landing.text()).match(/name="csrf" value="([^"]+)"/)?.[1];
 assert.ok(csrf);
 const firstCookie=cookie(landing);
 assert.equal((await send('/auth/email',form({email:'demo@example.test',csrf:'wrong'},firstCookie))).status,403);
 assert.equal((await send('/auth/email',form({email:'demo@example.test',csrf},firstCookie,'https://evil.example.test'))).status,403);
 assert.equal((await send('/auth/email',form({email:'not-an-email',csrf},firstCookie))).status,400);
 const response=await send('/auth/email',form({email:'demo@example.test',csrf},firstCookie));
 assert.equal(response.status,303);
 const params=calls.find(x=>x.action==='authorize').params;
 assert.equal(params.auth_method,'magic_link');
 assert.equal(params.login_hint,'demo@example.test');
 assert.equal(params.return_to,`${origin}/login?sent=1`);
});

test('callback converts PKCE transaction to verified account session without exposing tokens',async()=>{
 const {send,calls}=stub();
 const start=await send('/auth/start?method=google');
 const callback=await send('/callback?code=example&state=state-value',{headers:{cookie:cookie(start)}});
 assert.equal(callback.status,303);
 assert.equal(callback.headers.get('location'),'/account');
 const grant=calls.find(x=>x.action==='token');
 assert.equal(grant.options.expectedState,'state-value');
 assert.equal(grant.options.pkceCodeVerifier,'pkce-verifier');
 assert.ok(grant.options.expectedNonce);
 const session=cookie(callback);
 const account=await send('/account',{headers:{cookie:session}});
 assert.equal(account.status,200);
 const text=await account.text();
 assert.match(text,/subject-42/);
 assert.match(text,/test@example\.test/);
 assert.doesNotMatch(session,/subject-42|test@example\.test/);
 const csrf=text.match(/name="csrf" value="([^"]+)"/)?.[1];
 assert.ok(csrf);
 assert.equal((await send('/logout',form({csrf:'wrong'},session))).status,403);
 assert.equal((await send('/logout',form({csrf},session))).status,303);
 assert.equal((await send('/callback?code=forged')).status,403);
});

test('tampered cookie is rejected and consent request uses Authward one-time confirmation',async()=>{
 const {send}=stub();
 const fresh=await send('/login');
 assert.equal((await send('/account',{headers:{cookie:cookie(fresh).slice(0,-4)+'AAAA'}})).status,303);
 const raw='client_id=authward-demo-hosted&scope=openid%20email&sig=opaque';
 const consent=await send('/consent?interaction_query='+encodeURIComponent(raw)+'&confirmation=one-time-token');
 assert.equal(consent.status,200);
 const html=await consent.text();
 assert.match(html,/Approve sign-in/);
 const csrf=html.match(/name="csrf" value="([^"]+)"/)?.[1];
 const resp=await send('/auth/consent',form({csrf,decision:'allow'},cookie(consent)));
 assert.equal(resp.status,303);
 const url=new URL(resp.headers.get('location'));
 assert.equal(url.origin,'https://auth.olaryn.com');
 assert.equal(url.pathname,'/interaction/consent');
 assert.equal(url.searchParams.get('confirmation'),'one-time-token');
 assert.equal(Buffer.from(url.searchParams.get('interaction_query_b64'),'base64url').toString(),raw);
 assert.match(resp.headers.get('set-cookie'),/Max-Age=0/);
});
