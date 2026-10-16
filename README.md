# Authward Demo App

A minimal, public example of **product-owned authentication using [Authward](https://auth.olaryn.com)**.

Instead of a simulated SaaS, it shows exactly two screens: **Sign in** and **Account** (after a real authenticated callback). Try Google, GitHub, passkey, or email magic-link sign-in. The app owns its UI; Authward handles identity and OAuth/OIDC.

## Run

Requires Node.js 22+ and a browser on the **same computer** as the development server.

```bash
git clone https://github.com/olaryn-lab/authward-demo-app.git
cd authward-demo-app
npm ci
npm start
```

Open **http://127.0.0.1:4402**. No API key, client creation or secret required. The hosted Authward service already has the public demo client `authward-demo-local` with PKCE S256 and the exact loopback callback registered. A login only counts as complete once you actually authenticate and the demo receives a verified OIDC callback.

For other environments, these defaults can be overridden with `PRODUCT_ORIGIN`, `PORT`, `AUTHWARD_ISSUER`, `AUTHWARD_CLIENT_ID` and `AUTHWARD_AUDIENCE`. The default audience is `https://demo.auth.olaryn.com`; no Beseam, Trevra or LemonCrow permissions are granted. `0.0.0.0` is not a valid OAuth redirect. A remote browser requires an explicitly registered, approved HTTPS development origin.

## What the code demonstrates

- Product-owned login and signup pages with provider actions and a minimal protected account page.
- OIDC discovery, Authorization Code + PKCE, state and nonce verification with `openid-client`.
- Signed Authward interaction forwarding, product-owned consent/device approval, and CSRF-protected forms.
- Product-side session clearing on sign-out (not complete upstream Authward logout).

This is a **reference, not production authentication middleware**. It uses in-memory session storage and doesn't implement distributed sessions, refresh-token rotation, full issuer logout, rate limiting, or complete API token validation. Don't deploy as-is for real customers. See Authward's [integration playbook](https://auth.olaryn.com/agent/setup-playbook.md) and [product integration contract](https://auth.olaryn.com/agent/product-integration-guide.md) before adapting it to Beseam, Trevra or another product.

```bash
npm run check
npm test
```
