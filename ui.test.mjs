import test from 'node:test';
import assert from 'node:assert/strict';
import {signIn, accountPage, consentPage, errorPage, auxiliaryPage} from './ui.mjs';

test('the demo sign-in offers only four compact methods with recognizable SVG icons', () => {
  const page=signIn();
  for(const [method,label] of [
    ['google','Continue with Google'],
    ['github','Continue with GitHub'],
    ['passkey','Sign in with a passkey'],
    ['magic','Continue with email'],
  ]) {
    assert.match(page,new RegExp(label));
    assert.match(page,new RegExp(`method=${method}`));
  }
  assert.equal((page.match(/<svg aria-hidden="true"/g)||[]).length,4);
  assert.doesNotMatch(page,/Explore sample dashboard|Total revenue|Commerce|Sample workspace|performance/i);
  assert.match(page,/Powered by/);
  assert.match(page,/node cli\.mjs login/);
  assert.match(page,/Copy CLI login command/);
  assert.match(page,/const button=e\.currentTarget/);
  assert.match(page,/no web server needed/);
});

test('interactive method forms retain CSRF and do not expose it in a GET URL', () => {
  const page=signIn({interactive:true,csrf:'csrf-token-demo'});
  assert.equal((page.match(/name="csrf" value="csrf-token-demo"/g)||[]).length,4);
  assert.match(page,/<input type="email"/);
  assert.match(page,/name="method" value="magic"/);
  assert.doesNotMatch(page, /\/auth\/start\?method=magic/);
});

test('the account screen shows only verified identity and logout with safe escaping', () => {
  const page=accountPage({sub:'subject-123',name:'Ada <script>',email:'ada@example.test'},'session-csrf');
  assert.match(page,/Authenticated with Authward/);
  assert.match(page,/ada@example\.test/);
  assert.match(page,/subject-123/);
  assert.match(page,/Ada &lt;script&gt;/);
  assert.doesNotMatch(page,/<h1>Ada <script>/);
  assert.match(page,/<form method="post" action="\/logout">/);
  assert.match(page,/name="csrf" value="session-csrf"/);
  assert.doesNotMatch(page,/Sample store|Total revenue|Recent orders/);
});

test('error and consent screens use the same focused identity layout', () => {
  assert.match(errorPage('<unsafe>'),/&lt;unsafe&gt;/);
  assert.match(auxiliaryPage('Authorize device','<p>Device</p>'),/Authward Demo/);
});

test('consent is a compact permission screen with explicit safe actions',()=>{
  const page=consentPage({csrf:'csrf-approval',scopes:['openid','profile','email','unknown:scope']});
  assert.match(page,/Approve sign-in\?/);
  assert.match(page,/Your profile and Your email address/);
  assert.match(page,/class="primary">Allow access/);
  assert.match(page,/>Deny access<\/button>/);
  assert.equal((page.match(/name="csrf" value="csrf-approval"/g)||[]).length,2);
  assert.doesNotMatch(page,/unknown:scope|uses the identity provider|Allow access to Demo App/);
});
