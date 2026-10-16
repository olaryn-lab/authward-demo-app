import { before, after, test } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { server } from './app.mjs';

let base;
before(async()=>{server.listen(0,'127.0.0.1');await once(server,'listening');base=`http://127.0.0.1:${server.address().port}`;});
after(async()=>{server.close();await once(server,'close');});
const request=(route,options={})=>fetch(base+route,{redirect:'manual',...options});

test('the application owns login, signup and email entry with provider icons',async()=>{
  for(const route of ['/','/login','/signup']) {
    const res=await request(route);
    assert.equal(res.status,200);
    assert.match(await res.text(),/Continue with Google|Sign in/);
    assert.match(res.headers.get('set-cookie')||'',/HttpOnly/);
  }
  const res=await request('/login');
  const body=await res.text();
  for(const label of ['Continue with Google','Continue with GitHub','Sign in with a passkey','Send sign-in link'])
    assert.match(body,new RegExp(label));
  assert.match(body,/<form method="post" action="\/auth\/email">/);
  assert.match(body,/<input type="email"/);
  assert.match(body,/node cli\.mjs login/);
  assert.doesNotMatch(body,/Total revenue|sample dashboard/i);
});

test('email submission requires an authenticated form and CSRF',async()=>{
  const noSession=await request('/auth/email',{method:'POST',body:new URLSearchParams({email:'user@example.test',csrf:'fake'})});
  assert.equal(noSession.status,403);
  const login=await request('/login');
  const cookie=login.headers.get('set-cookie')?.split(';')[0]||'';
  const csrf=(await login.text()).match(/name="csrf" value="([^"]+)"/)?.[1];
  assert.ok(csrf);
  const malformed=await request('/auth/email',{method:'POST',headers:{cookie,origin:'http://127.0.0.1:4402'},body:new URLSearchParams({email:'not-an-email',csrf})});
  assert.equal(malformed.status,400);
  const crossSite=await request('/auth/email',{method:'POST',headers:{cookie,origin:'https://attacker.test'},body:new URLSearchParams({email:'user@example.test',csrf})});
  assert.equal(crossSite.status,403);
});

test('protected account refuses unauthenticated and forged callbacks',async()=>{
  const account=await request('/account');
  assert.equal(account.status,303);
  assert.equal(account.headers.get('location'),'/auth/start');
  const fake=await request('/callback?code=fake&state=fake');
  assert.equal(fake.status,403);
  assert.match(await fake.text(),/session expired/i);
});

test('the consent screen delegates protocol to Authward and requires a one-time local CSRF form',async()=>{
  const raw='client_id=authward-demo-local&scope=openid%20email&sig=opaque';
  const response=await request('/consent?interaction_query='+encodeURIComponent(raw)+'&confirmation=approval');
  assert.equal(response.status,200);
  const html=await response.text();
  assert.match(html,/Approve sign-in/);
  assert.match(html,/Allow access/);
  assert.match(html,/Deny access/);
  const cookie=response.headers.get('set-cookie')?.split(';')[0];
  const csrf=html.match(/name="csrf" value="([^"]+)"/)?.[1];
  assert.ok(cookie&&csrf);
  const forbidden=await request('/auth/consent',{method:'POST',headers:{cookie,origin:'https://evil.test'},body:new URLSearchParams({csrf,decision:'allow'})});
  assert.equal(forbidden.status,403);
  const accepted=await request('/auth/consent',{method:'POST',headers:{cookie,origin:'http://127.0.0.1:4402'},body:new URLSearchParams({csrf,decision:'allow'})});
  assert.equal(accepted.status,303);
  const url=new URL(accepted.headers.get('location'));
  assert.equal(url.origin,'https://auth.olaryn.com');
  assert.equal(url.pathname,'/interaction/consent');
  assert.equal(Buffer.from(url.searchParams.get('interaction_query_b64'),'base64url').toString(),raw);
  const replay=await request('/auth/consent',{method:'POST',headers:{cookie,origin:'http://127.0.0.1:4402'},body:new URLSearchParams({csrf,decision:'allow'})});
  assert.equal(replay.status,403);
});

test('logout requires a same-origin CSRF-authenticated session',async()=>{
  const r=await request('/logout',{method:'POST',headers:{origin:'http://127.0.0.1:4402'},body:'csrf=fake'});
  assert.equal(r.status,403);
});
