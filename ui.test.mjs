import { test } from 'node:test';
import assert from 'node:assert/strict';
import {accountPage,errorPage} from './ui.mjs';

test('only shows verified identity, safely escaped, and sign-out form',()=>{
  const result=accountPage({sub:'abc-123',name:'<script>demo</script>',email:'demo@example.test'},'csrf-token');
  assert.match(result,/Authenticated by production Authward/);
  assert.match(result,/abc-123/);
  assert.match(result,/demo@example\.test/);
  assert.match(result,/&lt;script&gt;demo&lt;\/script&gt;/);
  assert.doesNotMatch(result,/<script>demo<\/script>/);
  assert.match(result,/method="post" action="\/logout"/);
  assert.match(result,/name="csrf" value="csrf-token"/);
  for(const action of ['Continue with Google','Send sign-in link','Allow access','Explore sample dashboard']){
    assert.doesNotMatch(result,new RegExp(action));
  }
});
test('error page offers retry without provider implementation',()=>{
  const result=errorPage('<untrusted>');
  assert.match(result,/&lt;untrusted&gt;/);
  assert.match(result,/href="\/"/);
});
