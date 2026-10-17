/** Authward relying-party demo UI. Keep the identity experience—not a fake SaaS. */
export function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, char => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[char]);
}

const icons = {
  google: `<svg aria-hidden="true" viewBox="0 0 24 24" width="20" height="20" xmlns="http://www.w3.org/2000/svg"><path fill="#4285F4" d="M21.35 12.23c0-.71-.06-1.43-.18-2.12H12v4.03h5.24a4.49 4.49 0 0 1-1.95 2.94v2.47h3.17c1.86-1.71 2.89-4.23 2.89-7.32Z"/><path fill="#34A853" d="M12 21.7c2.66 0 4.9-.88 6.53-2.39l-3.17-2.47c-.88.59-2.01.94-3.36.94-2.58 0-4.77-1.75-5.55-4.1H3.18v2.55A9.85 9.85 0 0 0 12 21.7Z"/><path fill="#FBBC05" d="M6.45 13.2a5.94 5.94 0 0 1 0-3.79V6.86H3.18a9.83 9.83 0 0 0 0 8.89l3.27-2.55Z"/><path fill="#EA4335" d="M12 5.32c1.41 0 2.67.48 3.66 1.43l2.91-2.91A9.34 9.34 0 0 0 12 1.3a9.85 9.85 0 0 0-8.82 5.56l3.27 2.55c.78-2.35 2.97-4.09 5.55-4.09Z"/></svg>`,
  github: `<svg aria-hidden="true" viewBox="0 0 24 24" width="20" height="20" fill="currentColor" xmlns="http://www.w3.org/2000/svg"><path d="M12 .75a11.25 11.25 0 0 0-3.56 21.92c.56.1.77-.24.77-.54 0-.27-.01-.98-.01-1.92-3.14.69-3.8-1.51-3.8-1.51-.51-1.3-1.25-1.65-1.25-1.65-1.02-.7.08-.68.08-.68 1.13.08 1.72 1.16 1.72 1.16 1.01 1.71 2.66 1.22 3.31.93.1-.73.39-1.22.71-1.5-2.51-.28-5.15-1.26-5.15-5.57 0-1.23.44-2.23 1.16-3.02-.12-.28-.5-1.43.11-2.98 0 0 .95-.3 3.09 1.15A10.83 10.83 0 0 1 12 6.19c.95 0 1.9.13 2.79.38 2.14-1.45 3.08-1.15 3.08-1.15.62 1.55.23 2.7.11 2.98.73.79 1.16 1.79 1.16 3.02 0 4.32-2.65 5.28-5.18 5.56.4.35.76 1.05.76 2.11v3.04c0 .3.2.65.78.54A11.25 11.25 0 0 0 12 .75Z"/></svg>`,
  passkey: `<svg aria-hidden="true" viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="8" cy="12" r="4"/><path d="M12 12h9l-2 2 2 2-2 2h-3v-3h-4"/></svg>`,
  email: `<svg aria-hidden="true" viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="5" width="18" height="14" rx="2"/><path d="m3 7 9 6 9-6"/></svg>`,
};

function page(title, content, { showCli = false } = {}) {
  return `<!doctype html><html lang="en"><head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="color-scheme" content="light"><title>${escapeHtml(title)} · Authward Demo</title>
  <style>
  :root{font-family:Inter,ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#20272d;background:#f8fafb;font-synthesis:none}
  *{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:28px 16px}
  .shell{width:100%;max-width:424px} .mark{display:flex;align-items:center;justify-content:center;gap:10px;margin-bottom:28px;font-size:17px;font-weight:750;letter-spacing:-.03em}
  .logo{display:grid;place-items:center;width:33px;height:33px;border-radius:10px;background:#244a87;color:white;font-size:21px;font-weight:800}
  .card{background:white;border:1px solid #e0e5ec;border-radius:16px;padding:34px 32px;box-shadow:0 14px 45px rgba(33,48,76,.035)}
  h1{font-size:25px;line-height:1.24;letter-spacing:-.045em;text-align:center;margin:0 0 9px;overflow-wrap:anywhere}p{margin:0}.sub{color:#697587;font-size:14px;text-align:center;margin-bottom:29px;line-height:1.5}
  .providers{display:grid;gap:10px}.provider{display:flex;align-items:center;justify-content:center;position:relative;gap:12px;width:100%;min-height:47px;padding:10px 16px;border:1px solid #d8dfe8;border-radius:9px;background:#fff;color:#20272d;font-size:14px;font-weight:600;font-family:inherit;line-height:1.35;cursor:pointer;text-decoration:none;transition:background .14s,border-color .14s}
  .provider svg{flex-shrink:0;position:absolute;left:15px}.provider:hover{background:#f6f8fa;border-color:#b8c4d1}.provider:focus-visible,.submit:focus-visible,a:focus-visible{outline:3px solid #97b5ec;outline-offset:2px}
  .divider{display:flex;align-items:center;gap:12px;margin:24px 0 19px;color:#85909b;font-size:12px}.divider:before,.divider:after{content:"";height:1px;flex:1;background:#e3e8ef}
  label{display:block;font-size:13px;font-weight:650;margin-bottom:7px}input{width:100%;height:46px;padding:0 13px;border:1px solid #ccd5df;border-radius:9px;font:inherit;color:#20272d;background:white}input:focus{outline:2px solid #88a9e8;outline-offset:1px}
  .submit{display:flex;align-items:center;justify-content:center;gap:9px;width:100%;border:0;border-radius:9px;padding:12px 15px;min-height:47px;background:#244a87;color:white;font-size:14px;font-weight:600;font-family:inherit;line-height:1.3;cursor:pointer;margin-top:12px}.submit:hover{background:#173b73}
  .guide-steps{padding:0 0 0 22px;margin:0 0 18px;color:#465366;font-size:13px;line-height:1.6}.guide-steps li{padding-left:4px;margin-bottom:12px}.guide-steps strong{color:#233449}
  .hint{margin-top:21px;color:#768394;font-size:12px;text-align:center}.hint a{color:#315999;text-decoration:none}.hint a:hover{text-decoration:underline}
  .notice{padding:11px 13px;margin:0 0 20px;background:#f0f6ff;border:1px solid #d6e5fb;border-radius:9px;color:#3b587a;font-size:13px}
  .identity{display:grid;gap:13px;margin:25px 0;border-top:1px solid #e8edf1;border-bottom:1px solid #e8edf1;padding:20px 0}.identity div{display:flex;flex-direction:column;gap:2px;min-width:0}.identity small{font-size:12px;color:#728092}.identity strong{font-size:14px;font-weight:600;overflow-wrap:anywhere}
  .status{display:inline-flex;align-items:center;gap:7px;color:#217a53;font-size:13px;font-weight:650}.dot{width:8px;height:8px;border-radius:50%;background:#29a46a}
  .actions{display:flex;gap:12px}.secondary{display:flex;justify-content:center;width:100%;min-height:44px;align-items:center;border:1px solid #d8dfe8;background:white;border-radius:9px;color:#333e4e;font-size:14px;font-weight:600;font-family:inherit;line-height:1.3;text-decoration:none;cursor:pointer}
  form{margin:0}.secondary:hover{background:#f5f7fb}.small{font-size:12px;color:#8390a0;line-height:1.6;text-align:center;margin-top:19px}.small a{color:#4f6590}
  .cli-demo{margin:16px 0 0;border:1px solid #e0e5ec;border-radius:12px;padding:12px 13px;background:#fff}.cli-heading{font-size:12px;font-weight:700;margin:0 0 8px;color:#697587}.cli-line{display:flex;align-items:center;gap:8px}.cli-line code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12px;flex:1;white-space:nowrap;color:#29394d;overflow-x:auto}.copy-cli{padding:6px 10px;border:1px solid #d8dfe8;background:#f9fbfd;border-radius:7px;cursor:pointer;color:#244a87;font-size:12px;font-weight:650}.copy-cli:hover{background:#edf4fe}.copy-cli:focus-visible{outline:3px solid #97b5ec;outline-offset:2px}
  .compact .card{padding:30px 32px}.compact h1{text-align:left;font-size:23px;margin:0 0 13px}.compact .sub{text-align:left;margin-bottom:14px}
  .auth-flow p{color:#5d6878;font-size:14px;line-height:1.6;margin:0 0 16px}
  .auth-flow .requested{border:1px solid #e3eaf0;border-radius:10px;padding:14px;margin:18px 0;background:#fafbfd}
  .auth-flow .requested b{display:block;margin-bottom:6px;font-size:13px}
  .auth-flow .requested span{color:#657385;font-size:13px}
  .auth-flow form{margin:0}.auth-flow form+form{margin-top:10px}
  .auth-flow form button{display:flex;align-items:center;justify-content:center;width:100%;min-height:45px;border-radius:9px;padding:11px 15px;border:1px solid #d8dfe8;background:white;color:#20272d;font-size:14px;font-weight:600;font-family:inherit;cursor:pointer;transition:background .14s}
  .auth-flow form button:hover{background:#f4f7fb}
  .auth-flow form button.primary{color:#fff;background:#244a87;border-color:#244a87}
  .auth-flow form button.primary:hover{background:#173b73}
  .auth-flow label{display:block;margin:12px 0 7px}
  .auth-flow input{width:100%;height:45px;padding:0 12px;border:1px solid #cbd4dd;border-radius:9px;font:inherit}
  .auth-flow form button:focus-visible{outline:3px solid #98b5ec;outline-offset:2px}

  @media(max-width:480px){.card{padding:27px 22px}.compact .card{padding:26px}.mark{margin-bottom:22px}body{padding:20px 14px}}
  </style></head><body><main class="shell"><div class="mark"><span class="logo" aria-hidden="true">A</span>Authward Demo</div>${content}${showCli ? `<aside class="cli-demo"><p class="cli-heading">CLI login · no web server needed</p><div class="cli-line"><code>node cli.mjs login</code><button type="button" class="copy-cli" aria-label="Copy CLI login command">Copy</button></div></aside><script>document.querySelector('.copy-cli').addEventListener('click',async e=>{const button=e.currentTarget;try{await navigator.clipboard.writeText('node cli.mjs login');button.textContent='Copied'}catch{button.textContent='Select command'}})</script>` : ''}<p class="small">Powered by <a href="https://auth.olaryn.com" rel="noopener noreferrer">Authward</a></p></main></body></html>`;
}

function provider(method,label,{interactive,csrf}){
  const labelHtml=`${icons[method]}<span>${label}</span>`;
  return `<a class="provider" href="/auth/start?method=${method}">${labelHtml}</a>`;
}

export function signIn({mode='login',interactive=false,csrf='',info=''}={}) {
  const heading=mode==='signup'?'Create an account':'Sign in';
  return page(heading,`<section class="card"><h1>${heading}</h1><p class="sub">Sign in to your account</p>
    ${info?`<p role="status" class="notice">${escapeHtml(info)}</p>`:''}
    <div class="providers">
      ${provider('google','Continue with Google',{interactive,csrf})}
      ${provider('github','Continue with GitHub',{interactive,csrf})}
      <a class="provider" href="/passkeys/sign-in">${icons.passkey}<span>Sign in with a passkey</span></a>
    </div>
    <p class="hint">Your device will ask for your demo passkey. <a href="/passkeys/sign-in">How it works</a> · <a href="/passkeys/setup">Set one up</a>.</p>
    <div class="divider">or continue with email</div>
    <form method="post" action="/auth/email"><label for="email">Email address</label><input type="email" name="email" id="email" placeholder="you@example.com" autocomplete="email" required><input type="hidden" name="csrf" value="${escapeHtml(csrf)}"><button type="submit" class="submit">${icons.email} Send sign-in link</button></form>
  </section>`,{showCli:true});
}

export function accountPage(account, csrf, {passkeyAdded=false}={}) {
  const display=account.name || account.email || 'Signed in';
  return page('Account',`<section class="card"><h1>${escapeHtml(display)}</h1><p class="sub"><span class="status"><span class="dot"></span> Authenticated with Authward</span></p>
    <div class="identity"><div><small>Email</small><strong>${escapeHtml(account.email||'Not shared by provider')}</strong></div><div><small>User ID</small><strong>${escapeHtml(account.sub)}</strong></div></div>
    ${passkeyAdded?'<p class="notice" role="status">Passkey added. You can use it next time you sign in.</p>':''}
    <a class="secondary" href="/passkeys/setup">Set up a passkey</a>
    <form method="post" action="/logout"><input type="hidden" name="csrf" value="${escapeHtml(csrf)}"><button type="submit" class="secondary">Sign out</button></form>
  </section>`);
}

export function passkeySetupPage({signedIn=false,native=false}={}) {
  return page('Set up a passkey',`<section class="card"><h1>Set up a passkey</h1>
    <p class="sub">Sign in next time with your fingerprint, face unlock, device PIN, or password manager.</p>
    <ol class="guide-steps"><li><strong>Sign in first.</strong> Use Google or GitHub to prove this is your account.</li>
    <li><strong>Save your passkey.</strong> Your device or password manager will ask where to save it.</li>
    <li><strong>Try it next time.</strong> Choose “Sign in with a passkey” on this demo.</li></ol>
    <p class="notice">${native?'Your passkey will be registered for <strong>this demo application</strong>. You stay on this site; Authward verifies the credential securely in the background.':'For security, the device prompt opens briefly on <strong>auth.olaryn.com</strong>, the domain that issues your passkey. You will return here afterward. This does not grant Authward workspace access.'}</p>
    <a class="submit" style="text-decoration:none" href="${signedIn?'/passkeys/enroll':'/login'}">${signedIn?(native?'Create a demo passkey':'Continue to secure passkey setup'):'Sign in to add a passkey'}</a>
    <a class="secondary" style="margin-top:12px" href="${signedIn?'/account':'/login'}">${signedIn?'Back to account':'Back to sign in'}</a>
  </section>`);
}

export function passkeySignInPage() {
  return page('Sign in with a passkey',`<section class="card"><h1>Use your passkey</h1>
    <p class="sub">Choose a passkey already saved in your device, password manager, or security key.</p>
    <ol class="guide-steps"><li><strong>Continue to secure verification.</strong> Your browser opens a short passkey step on auth.olaryn.com.</li>
    <li><strong>Choose a saved passkey.</strong> Confirm with Face ID, fingerprint, PIN, or your security key.</li>
    <li><strong>Return signed in.</strong> After verification you come back to this demo account.</li></ol>
    <a class="submit" style="text-decoration:none" href="/auth/start?method=passkey">${icons.passkey} Continue with passkey</a>
    <p class="hint">No passkey yet? <a href="/passkeys/setup">Learn how to add one</a>.</p>
    <a class="secondary" style="margin-top:12px" href="/login">Use Google, GitHub, or email instead</a>
  </section>`);
}

export function consentPage({csrf,scopes=[]}={}) {
  const allowed=new Set(scopes.filter(value=>['openid','profile','email'].includes(value)));
  const shared=[...(allowed.has('profile')?['Your profile']:[]),...(allowed.has('email')?['Your email address']:[])];
  const description=shared.length ? shared.join(' and ') : 'Your identity';
  return page('Access approval',`<section class="card compact"><h1>Approve sign-in?</h1><p class="sub" style="text-align:left">Authward Demo is requesting permission to continue.</p>
    <div class="auth-flow"><div class="requested"><b>Requested access</b><span>${escapeHtml(description)}</span></div>
      <form method="post" action="/auth/consent"><input type="hidden" name="decision" value="allow"><input type="hidden" name="csrf" value="${escapeHtml(csrf)}"><button type="submit" class="primary">Allow access</button></form>
      <form method="post" action="/auth/consent"><input type="hidden" name="decision" value="deny"><input type="hidden" name="csrf" value="${escapeHtml(csrf)}"><button type="submit">Deny access</button></form>
    </div>
  </section>`);
}

export function errorPage(message='Please try again.') {
  return page('Error',`<section class="card"><h1>Couldn't continue</h1><p class="sub">${escapeHtml(message)}</p><a class="secondary" href="/login">Back to sign in</a></section>`);
}

export function auxiliaryPage(title, content) {
  return page(title,`<section class="card compact"><h1>${escapeHtml(title)}</h1><div class="auth-flow">${content}</div></section>`);
}

// Product-domain native WebAuthn. The challenge/verification server remains
// Authward, but `navigator.credentials.*` executes on this application's URL.
const nativePasskeyJavaScript=`
const status=document.querySelector('#passkey-status');
const action=document.querySelector('#passkey-retry');
const mode=document.querySelector('[data-passkey-mode]')?.dataset.passkeyMode;
const csrf=document.querySelector('[data-passkey-mode]')?.dataset.csrf;
const decode=value=>Uint8Array.from(atob(value.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-value.length%4)%4)),c=>c.charCodeAt(0));
const encode=value=>{let s='';for(const b of new Uint8Array(value))s+=String.fromCharCode(b);return btoa(s).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/g,'')};
function optionsJSON(options,registration){
  const o={...options,challenge:decode(options.challenge)};
  if(registration){o.user={...options.user,id:decode(options.user.id)};
    o.excludeCredentials=(options.excludeCredentials||[]).map(v=>({...v,id:decode(v.id)}))}
  else{o.allowCredentials=(options.allowCredentials||[]).map(v=>({...v,id:decode(v.id)}))}
  return o;
}
function credentialJSON(credential,registration){
  if(typeof credential.toJSON==='function')return credential.toJSON();
  const response=registration?{
    clientDataJSON:encode(credential.response.clientDataJSON),attestationObject:encode(credential.response.attestationObject),
    transports:credential.response.getTransports?.()||[]
  }: {clientDataJSON:encode(credential.response.clientDataJSON),authenticatorData:encode(credential.response.authenticatorData),
    signature:encode(credential.response.signature),userHandle:credential.response.userHandle?encode(credential.response.userHandle):null};
  return {id:credential.id,rawId:encode(credential.rawId),type:'public-key',response,
    clientExtensionResults:credential.getClientExtensionResults?.()||{}};
}
async function post(endpoint,body){
  const response=await fetch('/api/passkeys/'+endpoint,{method:'POST',credentials:'same-origin',
    headers:{'content-type':'application/json','x-csrf-token':csrf},body:JSON.stringify(body)});
  const data=await response.json().catch(()=>({}));
  if(!response.ok)throw Error(data.error||'Passkey request failed');
  return data;
}
let running=false;
async function run(){
  if(running)return;
  if(!window.PublicKeyCredential||!navigator.credentials){status.textContent='Passkeys are not supported in this browser. Try Chrome or another sign-in method.';action.hidden=false;return}
  running=true;action.hidden=true;status.textContent='Waiting for your device or password manager…';status.dataset.error='false';
  try{
    const registration=mode==='register';
    const label=registration?document.querySelector('#passkey-name')?.value.trim()||'':'';
    const challenge=await post(registration?'registration/options':'authentication/options',{});
    const publicKey=optionsJSON(challenge.options,registration);
    const credential=await (registration?navigator.credentials.create({publicKey}):navigator.credentials.get({publicKey}));
    if(!credential)throw Object.assign(Error('Cancelled'),{name:'NotAllowedError'});
    const verified=await post(registration?'registration/verify':'authentication/verify',
      {response:credentialJSON(credential,registration),...(label?{label}:{})});
    if(!verified.ok)throw Error('Passkey was not verified');
    status.textContent='Passkey verified. Opening your account…';
    location.replace('/account'+(registration?'?passkey=added':''));
  }catch(error){
    const cancelled=['NotAllowedError','AbortError'].includes(error?.name);
    status.textContent=cancelled?'Passkey prompt cancelled. You can try again.':error instanceof Error?error.message:'Passkey verification failed';
    status.dataset.error='true';action.hidden=false;
  }finally{running=false}
}
action.addEventListener('click',()=>void run());
void run();
`;

export function nativePasskeyPage({csrf='',mode='authenticate'}={}) {
  const registering=mode==='register';
  return page(registering?'Create a passkey':'Sign in with a passkey',
    `<section class="card" data-passkey-mode="${registering?'register':'authenticate'}" data-csrf="${escapeHtml(csrf)}">
      <h1>${registering?'Create your passkey':'Sign in with your passkey'}</h1>
      <p class="sub">${registering?'Save a passkey on this device or in your password manager.':'Your device or password manager should show your saved passkeys now.'}</p>
      ${registering?'<label for="passkey-name">Name (optional)</label><input id="passkey-name" maxlength="80" placeholder="My phone" autocomplete="off">':''}
      <p class="notice">Your passkey belongs to <strong>this demo application</strong>, not the Authward developer workspace. Verification happens securely without leaving this page.${registering?'':' Passkeys previously created for auth.olaryn.com are not transferable—set up a new demo passkey first.'}</p>
      <p id="passkey-status" role="status" aria-live="polite">Preparing secure verification…</p>
      <button id="passkey-retry" class="submit" type="button" hidden>${registering?'Try saving passkey again':'Try passkey again'}</button>
      <a class="secondary" href="${registering?'/account':'/login'}">${registering?'Back to account':'Use another sign-in method'}</a>
    </section><script>${nativePasskeyJavaScript}</script>`);
}
