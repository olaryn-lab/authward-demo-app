import { test } from 'node:test';
import assert from 'node:assert/strict';
import {login, publicDeviceInstructions, publicIdentity} from './cli.mjs';

test('CLI shows a verification URL and code, never the device secret',()=>{
  const line=publicDeviceInstructions({verification_uri:'http://127.0.0.1:4402/device',user_code:'ABCD-EFGH',device_code:'SENSITIVE'});
  assert.match(line,/127\.0\.0\.1:4402\/device/);
  assert.match(line,/ABCD-EFGH/);
  assert.doesNotMatch(line,/SENSITIVE/);
});

test('CLI reports a verified identity without tokens and uses a distinct native client',async()=>{
  const calls=[],messages=[];
  const client={
    async discovery(url,id) {calls.push({kind:'discovery',issuer:String(url),id});return {identity:'fixture'};},
    async initiateDeviceAuthorization(_config,params) {calls.push({kind:'start',params});return {verification_uri:'http://127.0.0.1:4402/device',user_code:'ABCD-EFGH',device_code:'SECRET'};},
    async pollDeviceAuthorizationGrant() {calls.push({kind:'poll'});return {access_token:'TOKEN',id_token:'ID_TOKEN',refresh_token:'REFRESH',claims:()=>({sub:'demo-subject',email:'user@example.test',name:'Demo User'})};},
  };
  const identity=await login({client,output:value=>messages.push(value)});
  assert.equal(calls[0].id,'authward-demo-cli');
  assert.deepEqual(calls[1].params,{scope:'openid profile email',resource:'https://demo.auth.olaryn.com'});
  assert.equal(calls[2].kind,'poll');
  assert.deepEqual(identity,{subject:'demo-subject',email:'user@example.test',name:'Demo User'});
  const printed=messages.join('\n');
  assert.match(printed,/Signed in through Authward/);
  for(const secret of ['SECRET','TOKEN','ID_TOKEN','REFRESH']) assert.doesNotMatch(printed,new RegExp(secret));
});

test('CLI refuses a token response without OIDC identity claims',()=>{
  assert.throws(()=>publicIdentity({claims:()=>({})}),/not verified/);
  assert.throws(()=>publicIdentity({}),/not verified/);
});
