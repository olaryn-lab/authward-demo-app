import { test } from 'node:test';
import assert from 'node:assert/strict';
import {signIn,accountPage,passkeySetupPage,passkeySignInPage,consentPage,errorPage} from './ui.mjs';

test('product-owned login shows real provider actions and email submission form',()=>{
  const html=signIn({csrf:'csrf-example'});
  for(const label of ['Continue with Google','Continue with GitHub','Sign in with a passkey','Send sign-in link']) assert.match(html,new RegExp(label));
  assert.equal((html.match(/<svg aria-hidden="true"/g)||[]).length,4);
  assert.match(html,/method="post" action="\/auth\/email"/);
  assert.match(html,/name="csrf" value="csrf-example"/);
  assert.match(html,/Copy CLI login command/);
  assert.match(html,/New to passkeys/);
  assert.match(html,/href="\/passkeys\/setup"/);
  assert.doesNotMatch(html,/Nook Commerce|Total revenue|Explore sample dashboard/);
});
test('real identity account is escaped and signs out with CSRF',()=>{
  const html=accountPage({sub:'sub-123',email:'person@example.test',name:'<script>'},'csrf-2');
  assert.match(html,/person@example\.test/);
  assert.match(html,/&lt;script&gt;/);
  assert.match(html,/name="csrf" value="csrf-2"/);
  assert.match(html,/method="post" action="\/logout"/);
  assert.match(html,/href="\/passkeys\/setup"/);
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

test('passkey onboarding stays product-branded, then explains the secure Authward ceremony',()=>{
 const signup=passkeySetupPage({signedIn:false});
 assert.match(signup,/Sign in to add a passkey/);
 assert.match(signup,/href="\/login"/);
 assert.doesNotMatch(signup,/href="https:\/\/auth\.olaryn\.com\/account/);
 const loggedIn=passkeySetupPage({signedIn:true});
 assert.match(loggedIn,/Continue to secure passkey setup/);
 assert.match(loggedIn,/href="\/passkeys\/enroll"/);
 assert.match(loggedIn,/auth\.olaryn\.com/);
 const signin=passkeySignInPage();
 assert.match(signin,/Choose a saved passkey/);
 assert.match(signin,/href="\/auth\/start\?method=passkey"/);
 assert.match(signin,/No passkey yet/);
 assert.match(accountPage({sub:'sub',email:'a@b.test'},'csrf',{passkeyAdded:true}),/Passkey added/);
});
