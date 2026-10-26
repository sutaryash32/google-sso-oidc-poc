# Google OAuth 2.0 Client ID Setup (for OIDC)

Do this in GCP Console — you can reuse the same GCP project used for the SAML
POC's service account (e.g. `secufusion-saml-poc`), since OAuth Client IDs and
service accounts are independent resources within a project.

## Step 1 — Start Keycloak first

```bash
docker compose up -d
```

Wait ~30s, then log into http://localhost:8280 (admin/admin) and import
`realm-google-oidc-poc.json` (Realm settings -> Add realm -> browse -> select file).

## Step 2 — OAuth consent screen (one-time, if not already configured)

1. console.cloud.google.com -> select your project
2. APIs & Services -> OAuth consent screen
3. User type: **Internal** (restricts login to your Workspace domain only —
   equivalent to the SAML POC's "ON for everyone" being scoped to the domain)
4. Fill in app name, support email, save

## Step 3 — Create the OAuth 2.0 Client ID

1. APIs & Services -> Credentials -> Create Credentials -> OAuth client ID
2. Application type: **Web application**
3. Name: e.g. `google-oidc-poc`
4. **Authorized redirect URIs** — add exactly this:
   ```
   http://localhost:8280/realms/google-oidc-poc/broker/google-oidc/endpoint
   ```
5. Create -> Google shows you a **Client ID** and **Client Secret**

## Step 4 — Put the Client ID/Secret into Keycloak

Fastest way: directly in the Admin Console (no re-import needed):

1. http://localhost:8280/admin -> realm `google-oidc-poc`
2. Identity Providers -> `google-oidc`
3. Fill in **Client ID** and **Client Secret** with the real values from Step 3
4. Save

## Step 5 — Test

1. http://localhost:8280/realms/google-oidc-poc/account
2. Click **"Sign in with Google"**
3. Log in with a `yserious.com` account (e.g. yash@yserious.com)
4. Confirm redirect back to a logged-in Keycloak account console page

## Notes

- No ngrok/tunnel needed — Google's OAuth redirect URI validation accepts
  plain `http://localhost` URIs for development, unlike the SAML flow which
  required HTTPS.
- Groups still don't come from the OIDC token — same Google-side limitation
  as SAML. The backend (`google-oidc-poc-backend/`) fetches groups separately
  via the Admin SDK Directory API, using the same service account +
  domain-wide delegation already set up for the SAML POC (reuse the same
  `google-service-account.json`, just copy it into this backend's
  `src/main/resources/` too).
