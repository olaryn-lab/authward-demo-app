# Authward Demo App

**A standalone, public, product-owned authentication example for [Authward](https://auth.olaryn.com/developer).**

This repository is the official small reference relying application for developers and coding agents integrating Authward. It is deliberately separate from the Authward identity backend. It demonstrates the same ownership boundary as Beseam and Trevra: **Authward issues identity and handles OIDC; the product owns its login, signup, account, consent, device approval, and logout UI.**

> **Educational reference—not production-ready middleware.** This example uses in-memory sessions and transactions, an intentionally simplified security model, and incomplete upstream credential revocation/logout. Do not deploy it for real users or treat its tests as a full authenticated end-user callback. See [Production gaps](#production-gaps) below.

## Quick start

Requires Node.js **22+**.

```bash
git clone https://github.com/olaryn-lab/authward-demo-app.git
cd authward-demo-app
npm ci
npm test
npm start
```

Open [http://127.0.0.1:4402](http://127.0.0.1:4402) to visit **Nook Commerce**, a small example SaaS application. Click **Explore sample dashboard** for an instant, clearly labeled sample workspace (no account, no fake login). Use **Sign in** to start a real Authward OAuth authorization and, after completing the real callback, enter the protected `/app` workspace.

Authward provides a dedicated public demo client **`authward-demo-local`** (Authorization Code with PKCE S256, **no client secret**), an isolated identity-only audience `https://demo.auth.olaryn.com`, and exact loopback callback `http://127.0.0.1:4402/callback`. These are the source defaults; the public client must also be present in the Authward deployment (otherwise authorization will fail). The resource's `interactionBaseUrl` is restricted to the demo's exact `http://127.0.0.1:4402` origin; normal Authward production clients keep HTTPS-only interaction origins. No Beseam, Trevra, or LemonCrow API permission is granted.

**Localhost works only when your browser and the demo server run on the same computer.** If your development environment is remote, use an explicitly approved HTTPS preview with its own properly registered callback; do not interpret remote localhost as a working browser URL.

Set these variables in your terminal or from an ignored `.env` file loaded by your development shell (the app does **not** automatically load dotenv):

```bash
export PRODUCT_NAME='Nook Commerce'
export PRODUCT_ORIGIN='http://127.0.0.1:4402'
export PORT=4402
export AUTHWARD_ISSUER='https://auth.olaryn.com'
export AUTHWARD_CLIENT_ID='authward-demo-local'
export AUTHWARD_AUDIENCE='https://demo.auth.olaryn.com'
npm start
```

Keep real secrets outside Git, never paste them into an agent chat, and never expose the local development server through a public tunnel without the developer's approval.

## What the app demonstrates

| Product route | Responsibility |
| --- | --- |
| `/` | Product-branded entry, not an Authward-hosted login page |
| `/login`, `/signup` | Product-owned interaction handoff and login method choices |
| `/auth/start`, `/callback` | OAuth code + PKCE client flow, state and nonce through `openid-client` |
| `/demo` and `/demo/*` | Instant sample dashboard, orders, products and settings with clear **not authenticated** labeling |
| `/app` and `/app/*` | Real protected dashboard accessible only after valid Authward code callback |
| `/account` | Redirect to protected product account settings |
| `/consent`, `/device` | Product-owned approval UX handing signed interactions back to Authward |
| `/logout` | Local product-session logout example (not complete issuer logout) |

The [code](./app.mjs) keeps signed `interaction_query` bytes opaque and forwards them to Authward headless continuations; the backend must verify the signature and interaction before granting anything. Product roles stay in the product's authorization layer. A WebAuthn passkey ceremony may briefly run on Authward's RP origin because browser credentials are RP-scoped.

## Coding agents: use this as a reference, not a scaffold to copy blindly

Read Authward's [public setup playbook](https://auth.olaryn.com/agent/setup-playbook.md) and [product integration contract](https://auth.olaryn.com/agent/product-integration-guide.md). Inspect the real target application's framework, session library, security headers, authentication state, deployment origin and existing clients. Preserve the product's UI and reuse existing Authward resources; do not introduce an independent identity issuer. Configure the exact registered callback, logout URL and resource-level `interactionBaseUrl` for the **actual browser-accessible product origin** before claiming success.

Use supported official CLI commands such as `pair-start` and `pair-status` for workspace authorization. Do not depend on a single long-lived tool process or take the user's “approved” message as credential verification. Ensure explicit audience, algorithm and app-specific scopes, correct cookie/CSRF/CSP/referrer behavior, and redacted request logs. **Run a real browser against the actual app URL and verify provider navigation**; a synthetic HTTP form is not enough. A full login is proven only after an actual successful callback with an authorized test account.

## Production gaps

- Replace all process-local session and transaction maps with durable, distributed storage and secure cryptographic session handling appropriate to the framework.
- Complete refresh-token rotation, access-token validation for protected APIs, issuer logout/end-session and revocation, robust consent and device flows, and tenant-aware business authorization.
- Use TLS, hardened CSRF/CSP and compatible referrer policy, configurable provider availability, rate limiting, audit logging with token/authorization-code redaction, monitoring and incident-ready session revocation.
- Add real provider/browser end-to-end tests and multi-instance lifecycle tests. The tests in this repository prove only example route behavior, not a production Authward login.

## Validate locally

```bash
npm run check
npm test
```

CI runs both on every pull request and push. The repository contains **no Authward client secrets or provider credentials** and is intended to remain publicly readable.

Source of truth: [olaryn-lab/authward-demo-app](https://github.com/olaryn-lab/authward-demo-app). Do not duplicate executable demo files inside the Authward production service.
