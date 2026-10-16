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
  if(interactive)return `<form method="post" action="/auth/method"><input type="hidden" name="method" value="${method}"><input type="hidden" name="csrf" value="${escapeHtml(csrf)}"><button type="submit" class="provider">${labelHtml}</button></form>`;
  return `<a class="provider" href="/auth/start?method=${method}">${labelHtml}</a>`;
}

export function signIn({mode='login',interactive=false,csrf='',info=''}={}) {
  const heading=mode==='signup'?'Create an account':'Sign in';
  return page(heading,`<section class="card"><h1>${heading}</h1><p class="sub">Try Authward authentication</p>
    ${info?`<p role="status" class="notice">${escapeHtml(info)}</p>`:''}
    <div class="providers">
      ${provider('google','Continue with Google',{interactive,csrf})}
      ${provider('github','Continue with GitHub',{interactive,csrf})}
      ${provider('passkey','Sign in with a passkey',{interactive,csrf})}
    </div>
    <div class="divider">or continue with email</div>
    ${interactive?`<form method="post" action="/auth/method"><label for="email">Email address</label><input type="email" name="email" id="email" placeholder="you@example.com" autocomplete="email" required><input type="hidden" name="method" value="magic"><input type="hidden" name="csrf" value="${escapeHtml(csrf)}"><button type="submit" class="submit">${icons.email} Send sign-in link</button></form>`:
    `<a class="submit" style="text-decoration:none" href="/auth/start?method=magic">${icons.email} Continue with email</a>`}
  </section>`,{showCli:true});
}

export function accountPage(account, csrf) {
  const display=account.name || account.email || 'Signed in';
  return page('Account',`<section class="card"><h1>${escapeHtml(display)}</h1><p class="sub"><span class="status"><span class="dot"></span> Authenticated with Authward</span></p>
    <div class="identity"><div><small>Email</small><strong>${escapeHtml(account.email||'Not shared by provider')}</strong></div><div><small>User ID</small><strong>${escapeHtml(account.sub)}</strong></div></div>
    <form method="post" action="/logout"><input type="hidden" name="csrf" value="${escapeHtml(csrf)}"><button type="submit" class="secondary">Sign out</button></form>
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
