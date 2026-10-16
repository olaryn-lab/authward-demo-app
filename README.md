# Authward Demo App

A **minimal OAuth/OIDC relying party** that uses the real production [Authward](https://auth.olaryn.com) sign-in, Google OAuth, GitHub OAuth, email magic links, passkeys and consent. The demo **does not implement any of these authentication screens or methods**.

## Browser login

```bash
git clone https://github.com/olaryn-lab/authward-demo-app.git
cd authward-demo-app
npm ci
npm start
```

Open `http://127.0.0.1:4402`. You are immediately redirected to **production Authward's own sign-in page**. Select Google, GitHub, or enter your email on Authward to request a real magic link. After Authward issues an authorization code, this app uses the maintained `openid-client` library to verify PKCE, state, nonce and OIDC identity, then shows a minimal account page. The account page exists only to demonstrate a **completed authenticated callback**.

The public `authward-demo-local` PKCE client and isolated `https://demo.auth.olaryn.com` audience are registered in production Authward. No app secret or local Authward server is required. Authward's installed providers and email delivery configuration determine the methods available—this demo does not supply or emulate them. The app uses in-memory sessions and is for local learning, not a production deployment. Run `npm test` to verify local routing and session protections; these tests do not prove upstream login or email delivery.

## Independent CLI login

Run the **separate native OAuth device flow** without starting the web app:

```bash
npm ci
node cli.mjs login
```

It requests a code using `authward-demo-cli`, displays the **hosted Authward** verification URL and user code, and waits for a real user to approve. It prints the verified subject (plus name/email if present). It does not log or store access/refresh/ID tokens. No localhost server is used.

This sample is not production-ready session middleware: it has process-local state and clears only the local session on sign-out. It is meant to demonstrate provider-hosted authentication and a successful application-side OIDC code exchange—not to recreate Authward.
