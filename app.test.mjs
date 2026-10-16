import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { server } from './app.mjs';

let base;
const clientId='demo-web';
before(async()=>{
  server.listen(0,'127.0.0.1');await once(server,'listening');
  base=`http://127.0.0.1:${server.address().port}`;
});
after(async()=>{server.close();await once(server,'close');});
const get=(route,options={})=>fetch(base+route,{redirect:'manual',...options});
const csrfFrom=html=>/name="csrf" value="([^"]+)"/.exec(html)?.[1];

test('app-owned login, signup, and account screens do not expose Authward branding',async()=>{
  for(const route of ['/','/login','/signup']) {
    const response=await get(route),body=await response.text();
    assert.equal(response.status,200);
    assert.match(body, /Example Store/);
    assert.doesNotMatch(body,/Sign in to Authward|Create an Authward account/);
  }
  const account=await get('/account');
  assert.equal(account.status,303);assert.equal(account.headers.get('location'),'/login');
});

test('fresh product-owned sign-in starts a first-party session for Authward handoff',async()=>{
  const envelope='client_id=demo-web&nonce=fresh&sig=opaque%2Bsignature';
  const landing=await get('/login?interaction_query='+encodeURIComponent(envelope));
  assert.equal(landing.status,200);
  const cookie=landing.headers.get('set-cookie')?.split(';')[0];
  assert.ok(cookie, 'new browser visitor receives first-party transaction cookie');
  const html=await landing.text();
  assert.match(html,/Sign in to Example Store/);
  const csrf=csrfFrom(html);
  assert.ok(csrf,'first landing has a CSRF token');
  const action=await get('/auth/method',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded',cookie},body:new URLSearchParams({csrf,method:'google'})});
  assert.equal(action.status,303);
  const target=new URL(action.headers.get('location'));
  assert.equal(target.origin,'https://auth.olaryn.com');
  assert.equal(target.pathname,'/interaction/login');
  assert.equal(target.searchParams.get('provider'),'google');
  assert.equal(Buffer.from(target.searchParams.get('interaction_query_b64'),'base64url').toString(),envelope);
  const unrelated=await get('/login?interaction_query='+encodeURIComponent('client_id=unrelated&sig=x'));
  assert.equal(unrelated.status,400);
});

test('consent forwards the original signed query unchanged and requires product CSRF',async()=>{
  const raw='client_id=demo-web&scope=openid%20profile&sig=opaque%2Bsignature';
  const page=await get('/consent?interaction_query='+encodeURIComponent(raw)+'&confirmation=demo-confirm');
  assert.equal(page.status,200);
  const html=await page.text();
  const cookie=page.headers.get('set-cookie').split(';')[0];
  const csrf=csrfFrom(html);
  assert.ok(csrf);
  const forbidden=await get('/auth/consent',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded',cookie},body:new URLSearchParams({csrf:'bad',decision:'allow'})});
  assert.equal(forbidden.status,403);
  const approved=await get('/auth/consent',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded',cookie},body:new URLSearchParams({csrf,decision:'allow'})});
  assert.equal(approved.status,303);
  const target=new URL(approved.headers.get('location'));
  assert.equal(target.origin,'https://auth.olaryn.com');
  assert.equal(target.pathname,'/interaction/consent');
  assert.equal(Buffer.from(target.searchParams.get('interaction_query_b64'),'base64url').toString(),raw);
  assert.equal(target.searchParams.get('decision'),'allow');
});

test('device approval requires per-session CSRF and uses Authward headless endpoint',async()=>{
  const page=await get('/device?user_code=XX-22&confirmation=demo-confirm');
  assert.equal(page.status,200);
  const html=await page.text(),cookie=page.headers.get('set-cookie').split(';')[0];
  const csrf=csrfFrom(html);
  const result=await get('/auth/device',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded',cookie,origin:'http://evil.invalid'},body:new URLSearchParams({csrf,decision:'approve'})});
  assert.equal(result.status,403);
  const valid=await get('/auth/device',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded',cookie},body:new URLSearchParams({csrf,decision:'deny'})});
  assert.equal(valid.status,303);
  const target=new URL(valid.headers.get('location'));
  assert.equal(target.pathname,'/interaction/device');
  assert.equal(target.searchParams.get('decision'),'deny');
});
