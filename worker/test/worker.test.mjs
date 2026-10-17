import {test} from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {createWorker} from '../src/index.mjs';

const origin='https://authward-demo.example.test';
const config={PUBLIC_ORIGIN:origin,SESSION_KEY:randomBytes(32).toString('base64url'),AUTHWARD_CLIENT_ID:'authward-demo-hosted'};
function stub({idClaims={sub:'subject-42',email:'test@example.test',name:'Demo User'},profile={sub:'subject-42',email:'test@example.test',name:'Demo User'},idToken='signed.idtoken.hint'}={}) {
 const calls=[];
 const client={
   async discovery(url,id){calls.push({action:'discovery',issuer:String(url),id});return {fixture:true};},
   randomPKCECodeVerifier(){return 'pkce-verifier';},
   randomState(){return 'state-value';},
   async calculatePKCECodeChallenge(verifier){assert.equal(verifier,'pkce-verifier');return 'challenge-value';},
   buildAuthorizationUrl(_cfg,params){calls.push({action:'authorize',params});return new URL('https://auth.olaryn.com/api/auth/oauth2/authorize?response_type=code');},
   async authorizationCodeGrant(_cfg,url,options){calls.push({action:'token',url:String(url),options});return {access_token:'private-access-token',id_token:idToken,claims:()=>idClaims};},
   async fetchUserInfo(_cfg,accessToken,expectedSubject){calls.push({action:'userinfo',expectedSubject});assert.equal(accessToken,'private-access-token');return profile;},
   buildEndSessionUrl(_cfg,params){calls.push({action:'logout',params});const uri=new URL('https://auth.olaryn.com/api/auth/oauth2/end-session');uri.searchParams.set('client_id','authward-demo-hosted');for(const [k,v] of Object.entries(params))uri.searchParams.set(k,v);return uri;},
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
  assert.equal(params.resource,'https://demo-hosted.auth.olaryn.com');
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
 const signedOut=await send('/logout',form({csrf},session));
 assert.equal(signedOut.status,303);
 const endSession=new URL(signedOut.headers.get('location'));
 assert.equal(endSession.origin,'https://auth.olaryn.com');
 assert.equal(endSession.pathname,'/api/auth/oauth2/end-session');
 assert.equal(endSession.searchParams.get('client_id'),'authward-demo-hosted');
 assert.equal(endSession.searchParams.get('post_logout_redirect_uri'),`${origin}/`);
 assert.equal(endSession.searchParams.get('id_token_hint'),'signed.idtoken.hint');
 assert.match(signedOut.headers.get('set-cookie'),/Max-Age=0/);
 assert.equal(calls.filter(x=>x.action==='logout').length,1);
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
 assert.match(resp.headers.get('set-cookie'),/Max-Age=900/);
 const afterConsent=await send('/auth/consent',form({csrf,decision:'allow'},cookie(resp)));
 assert.equal(afterConsent.status,403);
});

test('approval preserves PKCE across consent and callback establishes the account',async()=>{
 const {send,calls}=stub();
 const start=await send('/auth/start?method=google');
 assert.equal(start.status,303);
 const raw='client_id=authward-demo-hosted&scope=openid%20email&sig=opaque';
 const approval=await send('/consent?interaction_query='+encodeURIComponent(raw)+'&confirmation=one-time-token',
   {headers:{cookie:cookie(start)}});
 const html=await approval.text();
 const csrf=html.match(/name="csrf" value="([^"]+)"/)?.[1];
 const consent=await send('/auth/consent',form({csrf,decision:'allow'},cookie(approval)));
 assert.equal(consent.status,303);
 // Simulate Authward's signed confirmation, upstream OAuth completion, then callback.
 const callback=await send('/callback?code=authorized&state=state-value',{headers:{cookie:cookie(consent)}});
 assert.equal(callback.status,303);
 assert.equal(callback.headers.get('location'),'/account');
 const account=await send('/account',{headers:{cookie:cookie(callback)}});
 assert.equal(account.status,200);
 assert.match(await account.text(),/test@example\.test/);
 assert.equal(calls.filter(x=>x.action==='token').length,1);
});

test('uses subject-bound UserInfo when ID token does not include email or name',async()=>{
 const {send,calls}=stub({idClaims:{sub:'subject-42'}});
 const start=await send('/auth/start?method=github');
 const callback=await send('/callback?code=authorized&state=state-value',{headers:{cookie:cookie(start)}});
 assert.equal(callback.status,303);
 assert.equal(calls.filter(x=>x.action==='userinfo').length,1);
 assert.equal(calls.find(x=>x.action==='userinfo').expectedSubject,'subject-42');
 const account=await send('/account',{headers:{cookie:cookie(callback)}});
 const view=await account.text();
 assert.match(view,/test@example\.test/);
 assert.match(view,/Demo User/);
});

test('rejects conflicting UserInfo subject before establishing an account',async()=>{
 const {send}=stub({idClaims:{sub:'subject-42'},profile:{sub:'someone-else',email:'wrong@example.test'}});
 const start=await send('/auth/start?method=google');
 const callback=await send('/callback?code=authorized&state=state-value',{headers:{cookie:cookie(start)}});
 assert.equal(callback.status,502);
 assert.equal(callback.headers.get('set-cookie'),null);
});

test('logout rejects cross-site requests and requires the logged-in session even when Authward SSO exists',async()=>{
 const {send,calls}=stub();
 const start=await send('/auth/start?method=google');
 const callback=await send('/callback?code=authorized&state=state-value',{headers:{cookie:cookie(start)}});
 const account=await send('/account',{headers:{cookie:cookie(callback)}});
 const csrf=(await account.text()).match(/name="csrf" value="([^"]+)"/)?.[1];
 const session=cookie(callback);
 assert.equal((await send('/logout',form({csrf},session,'https://attacker.test'))).status,403);
 assert.equal((await send('/logout',form({csrf:'forged'},session))).status,403);
 assert.equal((await send('/logout',form({csrf},''))).status,403);
 assert.equal(calls.filter(x=>x.action==='logout').length,0);
 const logout=await send('/logout',form({csrf},session));
 assert.equal(logout.status,303);
 assert.equal(calls.filter(x=>x.action==='logout').length,1);
});

test('large OIDC identity tokens never exceed the encrypted cookie limit; logout still asks Authward to terminate SSO',async()=>{
 const largeToken='x'.repeat(2200);
 const {send}=stub({idToken:largeToken});
 const start=await send('/auth/start?method=google');
 const callback=await send('/callback?code=authorized&state=state-value',{headers:{cookie:cookie(start)}});
 assert.equal(callback.status,303);
 assert.ok(cookie(callback).length<3900,'encrypted session fits browser cookie size');
 const account=await send('/account',{headers:{cookie:cookie(callback)}});
 assert.equal(account.status,200);
 const csrf=(await account.text()).match(/name="csrf" value="([^"]+)"/)?.[1];
 const logout=await send('/logout',form({csrf},cookie(callback)));
 assert.equal(new URL(logout.headers.get('location')).searchParams.get('id_token_hint'),largeToken);
 const oversized=stub({idToken:'x'.repeat(4000)});
 const first=await oversized.send('/auth/start?method=google');
 const second=await oversized.send('/callback?code=authorized&state=state-value',{headers:{cookie:cookie(first)}});
 const localCookie=cookie(second);
 assert.ok(localCookie.length<3900);
 const page=await oversized.send('/account',{headers:{cookie:localCookie}});
 const fallbackCsrf=(await page.text()).match(/name="csrf" value="([^"]+)"/)?.[1];
 const last=await oversized.send('/logout',form({csrf:fallbackCsrf},localCookie));
 const target=new URL(last.headers.get('location'));
 assert.equal(target.pathname,'/api/auth/oauth2/end-session');
 assert.equal(target.searchParams.has('id_token_hint'),false);
});

test('passkey guide is product-owned and enrollment requires an authenticated app session',async()=>{
 const {send}=stub();
 const start=await send('/passkeys/setup');
 assert.equal(start.status,200);
 assert.match(await start.text(),/Sign in to add a passkey/);
 const signin=await send('/passkeys/sign-in');
 assert.equal(signin.status,200);
 assert.match(await signin.text(),/Choose a saved passkey/);
 const denied=await send('/passkeys/enroll');
 assert.equal(denied.status,303);
 assert.equal(denied.headers.get('location'),'/login');
 const oauth=await send('/auth/start?method=google');
 const callback=await send('/callback?code=valid&state=state-value',{headers:{cookie:cookie(oauth)}});
 const appCookie=cookie(callback);
 const guide=await send('/passkeys/setup',{headers:{cookie:appCookie}});
 assert.match(await guide.text(),/Continue to secure passkey setup/);
 const bridge=await send('/passkeys/enroll',{headers:{cookie:appCookie}});
 assert.equal(bridge.status,303);
 assert.equal(new URL(bridge.headers.get('location')).origin,'https://auth.olaryn.com');
 assert.equal(new URL(bridge.headers.get('location')).pathname,'/passkeys/enroll');
 assert.equal(new URL(bridge.headers.get('location')).searchParams.get('client_id'),'authward-demo-hosted');
});
