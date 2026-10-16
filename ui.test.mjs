import { test } from 'node:test';
import assert from 'node:assert/strict';
import {signIn,accountPage,consentPage,errorPage} from './ui.mjs';

test('product-owned login shows real provider actions and email submission form',()=>{
  const html=signIn({csrf:'csrf-example'});
  for(const label of ['Continue with Google','Continue with GitHub','Sign in with a passkey','Send sign-in link']) assert.match(html,new RegExp(label));
  assert.equal((html.match(/<svg aria-hidden="true"/g)||[]).length,4);
  assert.match(html,/method="post" action="\/auth\/email"/);
  assert.match(html,/name="csrf" value="csrf-example"/);
  assert.match(html,/Copy CLI login command/);
  assert.doesNotMatch(html,/Nook Commerce|Total revenue|Explore sample dashboard/);
});
test('real identity account is escaped and signs out with CSRF',()=>{
  const html=accountPage({sub:'sub-123',email:'person@example.test',name:'<script>'},'csrf-2');
  assert.match(html,/person@example\.test/);
  assert.match(html,/&lt;script&gt;/);
  assert.match(html,/name="csrf" value="csrf-2"/);
  assert.match(html,/method="post" action="\/logout"/);
});
test('application consent UI forwards only local decision and no OAuth provider logic',()=>{
  const html=consentPage({csrf:'csrf-3',scopes:['openid','profile','email']});
  assert.match(html,/Approve sign-in/);
  assert.match(html,/Allow access/);
  assert.match(html,/Deny access/);
  assert.equal((html.match(/name="csrf" value="csrf-3"/g)||[]).length,2);
  assert.doesNotMatch(html,/Google SDK|GitHub SDK/);
});
test('errors escape untrusted strings',()=>{
  assert.match(errorPage('<img src=x>'),/&lt;img src=x&gt;/);
});
