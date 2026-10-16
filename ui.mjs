/** The sole UI owned by the demo: showing a verified OIDC result and logout. */
const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function page(title, content) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)} · Authward Demo</title><style>
  :root{font:15px/1.5 system-ui,-apple-system,sans-serif;color:#1f2937;background:#f8fafc}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:20px}.card{width:min(410px,100%);border:1px solid #e2e8f0;border-radius:16px;background:white;padding:32px;box-shadow:0 10px 35px #1728420a}h1{font-size:24px;line-height:1.25;margin:0 0 9px;letter-spacing:-.03em}.muted{color:#64748b;margin:0 0 24px}dl{border-top:1px solid #e2e8f0;padding-top:12px}dt{color:#64748b;font-size:12px;margin-top:12px}dd{margin:2px 0 0;font-weight:600;overflow-wrap:anywhere}button,a.button{width:100%;display:block;text-align:center;border:1px solid #cbd5e1;border-radius:9px;padding:11px;background:#234887;color:#fff;font:600 14px/1.4 system-ui;cursor:pointer;text-decoration:none}button:hover,a.button:hover{background:#183b75}.success{color:#147d4c;font-size:13px;font-weight:700}form{margin-top:22px}</style></head><body><main class="card">${content}</main></body></html>`;
}
export function accountPage(account, csrf) {
  return page('Signed in',`<h1>Signed in</h1><p class="muted"><span class="success">✓</span> Authenticated by production Authward</p><dl><dt>Name</dt><dd>${escapeHtml(account.name||'Not shared')}</dd><dt>Email</dt><dd>${escapeHtml(account.email||'Not shared')}</dd><dt>OIDC subject</dt><dd>${escapeHtml(account.sub)}</dd></dl><form method="post" action="/logout"><input type="hidden" name="csrf" value="${escapeHtml(csrf)}"><button type="submit">Sign out</button></form>`);
}
export function errorPage(message) {
  return page('Login error',`<h1>Unable to continue</h1><p class="muted">${escapeHtml(message)}</p><a class="button" href="/">Try again with Authward</a>`);
}
