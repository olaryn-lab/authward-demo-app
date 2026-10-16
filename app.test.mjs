import { before, after, test } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { server } from './app.mjs';

let base;
before(async()=>{server.listen(0,'127.0.0.1');await once(server,'listening');base=`http://127.0.0.1:${server.address().port}`;});
after(async()=>{server.close();await once(server,'close');});
const get=(route,options={})=>fetch(base+route,{redirect:'manual',...options});

test('the demo does not serve its own Google/GitHub/email login UI',async()=>{
  for(const route of ['/','/login','/signup']){
    const r=await get(route);
    assert.equal(r.status,303);
    assert.equal(r.headers.get('location'),'/auth/start');
  }
});
test('protected account requires a real OAuth session',async()=>{
  const account=await get('/account');
  assert.equal(account.status,303);
  assert.equal(account.headers.get('location'),'/auth/start');
});
test('callback cannot complete without a valid OAuth state',async()=>{
  const r=await get('/callback?code=fake&state=fake');
  assert.equal(r.status,403);
  assert.match(await r.text(),/session expired/i);
});
test('legacy fake dashboard and custom consent are absent',async()=>{
  for(const route of ['/demo','/app','/auth/method','/auth/consent','/consent','/device']){
    const r=await get(route);
    assert.equal(r.status,404,route);
  }
});
test('logout requires real authentication and a same-origin CSRF proof',async()=>{
  const r=await get('/logout',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded','origin':base},body:'csrf=fake'});
  assert.equal(r.status,403);
});
