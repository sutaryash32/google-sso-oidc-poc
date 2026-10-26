# Google Workspace SSO via Keycloak (OIDC) — POC Guide & Production Playbook

> **Update:** this guide describes the original single-domain POC. The system is now multi-tenant, with
> `yserious.com` as tenant #1 in the same realm and with the same client ids. The Google/Keycloak setup
> steps below are still accurate; for how login, tenant enforcement and adding tenants work now, see
> [the project README](../README.md) and [multi_tenant_saas_design.md](multi_tenant_saas_design.md). In particular, Hosted
> Domain is now `*` (the tenant registry is the boundary), and the backend no longer has a separate single-tenant mode.


This document explains how the proof of concept works end to end, what was
verified, what is deliberately *not* production-ready, and how to integrate
the same pattern into a real running project.

- Domain: `yserious.com` (Google Workspace)
- Protocol: OIDC only (no SAML)
- Keycloak 24.0.3 is the identity broker; Spring Boot only validates Keycloak JWTs

> The sibling file `README.md` covers run order and ports. This file covers
> the *why*, the flow, and the path to production.

---

## 1. What the POC proves

| Capability | Status |
|---|---|
| Any `@yserious.com` user signs in with Google | Verified (`yash@yserious.com`) |
| Keycloak brokers Google and issues its own JWT | Verified |
| Spring Boot validates the Keycloak JWT (signature, issuer, expiry) | Verified |
| `/api/me` returns identity and roles from the JWT | Verified |
| Google Groups fetched server-side via Admin SDK Directory API | Verified (`secufusion-admins`, `sfn-viewers`) |
| Non-domain accounts (e.g. personal Gmail) are rejected | **Not yet tested** — see §8 |
| Second Workspace user (`test@yserious.com`) | **Not yet tested** — see §8 |
| Audience / email-domain validation in the backend | **Not implemented** — see §7 |
| `identity_provider` claim in the token | **Not working yet** (shows blank) — cosmetic, see §9 |

---

## 2. Architecture

```
 ┌────────────┐   1. login redirect    ┌───────────────────────┐
 │  React SPA │ ─────────────────────▶ │  Keycloak (broker)    │
 │ :5173      │                        │  realm google-oidc-poc│
 │ keycloak-js│                        │  :8280                │
 └─────┬──────┘                        └──────────┬────────────┘
       │                                          │ 2. redirect to Google
       │                                          ▼    (hd=yserious.com)
       │                                ┌───────────────────────┐
       │                                │ Google Workspace OIDC │
       │                                │ accounts.google.com   │
       │                                └──────────┬────────────┘
       │            3. code ◀──────────────────────┘
       │            4. Keycloak exchanges code, creates/updates local
       │               user, issues ITS OWN access token (JWT)
       │ 5. SPA receives Keycloak tokens (auth code + PKCE)
       │
       │ 6. API call, Authorization: Bearer <Keycloak JWT>
       ▼
 ┌───────────────────────┐   7. fetch JWKS once, validate locally
 │ Spring Boot :8095     │ ─────────────────────▶ Keycloak /certs
 │ Resource Server       │
 │  /api/me              │   8. groups: service account impersonates an
 │  /api/users/{e}/groups│ ─────────────────────▶ admin → Directory API
 └───────────────────────┘
```

Key points:

1. **Two separate trust relationships.** Google trusts *Keycloak* (as an OAuth
   client). The backend trusts *Keycloak* (as the token issuer). The backend
   never talks to Google for authentication and never sees a Google token.
2. **Keycloak issues its own JWT.** Claims in it (`email`, `name`, roles) are
   what the backend reads. Google's ID token is consumed by Keycloak only.
3. **Groups do not come from Google's OIDC token.** Google does not put group
   membership in OIDC ID tokens. The backend fetches them separately.

---

## 3. Components and configuration

| Piece | Where | Notes |
|---|---|---|
| Keycloak + Postgres | `google-oidc-poc-keycloak/docker-compose.yml` | Own network `oidc-poc-net`, own volume `oidc_poc_db_data`, containers `oidc-poc-keycloak` / `oidc-poc-keycloak-db`, port 8280 |
| Realm | `realm-google-oidc-poc.json` (imported manually) | Realm name must be exactly `google-oidc-poc` |
| Backend | `google-oidc-poc-backend/` | Spring Boot 3.3.1, Java 17, port 8095 |
| Frontend | `google-oidc-poc-frontend/` | React + Vite + `keycloak-js`, port 5173 |

### 3.1 Google Cloud OAuth client

| Setting | Value |
|---|---|
| Consent screen user type | **Internal** (only works if the GCP project belongs to the `yserious.com` organization) |
| Application type | Web application |
| Authorized redirect URI | `http://localhost:8280/realms/google-oidc-poc/broker/google-oidc/endpoint` |
| Authorized JavaScript origins | Not needed (Keycloak does a server-side code exchange) |
| Scopes | `openid email profile` |

The redirect URI pattern is `{keycloak-base}/realms/{realm}/broker/{idp-alias}/endpoint`,
so the Keycloak IdP alias **must** be `google-oidc`. Browse via `localhost`,
not `127.0.0.1`, or Google returns `redirect_uri_mismatch`.

### 3.2 Keycloak Identity Provider (`google-oidc`)

| Setting | Value |
|---|---|
| Provider | Google |
| Alias | `google-oidc` |
| Client ID / Secret | From the Google OAuth client (enter in the admin console, never in git) |
| Hosted Domain | `yserious.com` |
| Default scopes | `openid email profile` |
| Trust Email | On |
| Sync mode | `FORCE` |

### 3.3 Keycloak client `google-oidc-poc-frontend`

Public client, standard flow, PKCE S256, redirect URI `http://localhost:5173/*`.
`directAccessGrantsEnabled` is off.

### 3.4 Backend

- `issuer-uri: http://localhost:8280/realms/google-oidc-poc` — Spring fetches
  the discovery document and JWKS from it. The `iss` claim in every token must
  match this string exactly.
- `google.workspace.delegated-admin-email` (env `GOOGLE_DELEGATED_ADMIN`,
  default `yash@yserious.com`) — the real admin the service account impersonates.
- `google.workspace.service-account-key-path` (env `GOOGLE_SA_KEY_PATH`,
  default `classpath:google-service-account.json`) — gitignored.
- The Directory client is `@Lazy`, so the app starts without the key; only the
  groups endpoint needs it.

### 3.5 Service account (groups lookup)

- Domain-wide delegation entry in Workspace Admin (Security → API controls):
  the service account's Client ID with scopes
  `admin.directory.group.readonly` and `admin.directory.user.readonly`.
- Admin SDK API enabled in the GCP project.

---

## 4. Login flow, step by step

1. User opens the SPA. `keycloak-js` runs `check-sso`; no session, so the
   "Sign in with Google Workspace" button shows.
2. Click calls `keycloak.login({ idpHint: 'google-oidc' })`. The browser goes
   to Keycloak's `/auth` endpoint with a PKCE challenge, and Keycloak
   immediately forwards to Google (the `idpHint` skips Keycloak's own login page).
3. Google authenticates the user. With an Internal consent screen only
   `yserious.com` accounts can complete this.
4. Google redirects to the Keycloak broker endpoint with an authorization code.
5. Keycloak exchanges the code (using the client secret), validates the ID
   token, and runs the **first broker login** flow on first use: it creates a
   local Keycloak user linked to the Google identity and assigns default roles.
6. Keycloak redirects back to the SPA with a code; `keycloak-js` redeems it
   (with the PKCE verifier) for access/refresh/ID tokens.
7. The SPA calls the backend with `Authorization: Bearer <access token>`.
8. Spring Security validates signature (JWKS), `iss`, and `exp`. `/api/me`
   maps claims to a response.
9. `/api/users/{email}/groups`: the backend builds a Directory client from the
   service account key, impersonating the delegated admin, and lists the
   user's groups.

---

## 5. Running the POC

```powershell
# 1. Keycloak + Postgres (separate containers, own network and volume)
cd google-oidc-poc-keycloak
docker compose up -d
# Admin console: http://localhost:8280/admin  (admin / admin — dev only)
# Create realm -> import realm-google-oidc-poc.json -> name: google-oidc-poc
# Identity providers -> google-oidc: paste Client ID/Secret, Hosted Domain, Trust Email

# 2. Backend
cd ..\google-oidc-poc-backend
# put google-service-account.json in src\main\resources\ (gitignored)
mvn spring-boot:run

# 3. Frontend
cd ..\google-oidc-poc-frontend
npm install
npm run dev        # http://localhost:5173
```

Log out with the app's **Logout** button. Logging out of Keycloak does *not*
log the browser out of Google; to test another user use an incognito window
or "Use another account" on Google's screen.

---

## 6. Issues hit during the POC (and fixes)

| Symptom | Cause | Fix |
|---|---|---|
| `docker compose ps` → "no configuration file provided" | Ran from repo root | Run from `google-oidc-poc-keycloak/` |
| Keycloak WARN "development mode" | `command: start-dev` | Expected for POC; use `start` in production |
| Backend crash: `google-service-account.json ... does not exist` | Key loaded eagerly at startup | `@Lazy` on the `Directory` bean and its injection point |
| `invalid_grant: Invalid email or User ID` | Impersonating a non-existent `admin@yserious.com` | Default delegated admin set to a real user |
| Blank page, console: "A 'Keycloak' instance can only be initialized once" | React StrictMode double-invokes effects in dev | Shared init promise in `App.jsx` |
| `/groups` returned 401 | Frontend sent no `Authorization` header on that call | Header added; groups errors no longer blank the page |
| Keycloak "We are sorry… Invalid username or password" with a 400 on `/auth` | Replayed/stale auth URL | Start from a fresh `http://localhost:5173` tab |

---

## 7. Domain restriction: how `yserious.com`-only is enforced

Layer these. None of them alone is sufficient.

1. **Internal OAuth consent screen (primary control).** Google itself refuses
   accounts outside the organization.
2. **Hosted Domain = `yserious.com` in Keycloak.** Sends the `hd` hint to
   Google and (as far as the Keycloak Google provider documents) rejects
   tokens whose `hd` claim does not match. The `hd` *request parameter* alone
   is only a UI hint and can be tampered with. **Verify with a personal Gmail
   account** (§8) rather than assuming.
3. **Backend validation (defence in depth) — not implemented yet.** Reject
   tokens whose `email` does not end in `@yserious.com` or whose
   `email_verified` is not true.

No custom authenticator or mapper is needed for a single domain.

---

## 8. Validation checklist

Run these before calling an environment "working".

1. `curl http://localhost:8280/realms/google-oidc-poc/.well-known/openid-configuration`
   → `issuer` is exactly `http://localhost:8280/realms/google-oidc-poc`.
2. IdP page in Keycloak shows the real Client ID and Hosted Domain `yserious.com`.
3. The IdP page's **Redirect URI** equals the one registered in Google Cloud.
4. Log in as a `yserious.com` user → lands in the app; the user appears under
   Keycloak **Users** with a federated identity link.
5. **Negative test:** log in with a personal `@gmail.com` account → must be
   refused by Google or Keycloak.
6. **Second user:** incognito, log in as `test@yserious.com` → a second Keycloak
   user is created, no "account already exists" page.
7. Decode the access token: check `iss`, `aud`, `email`, `email_verified`,
   `realm_access.roles`.
8. `GET /api/public` → 200; protected endpoint without a token → 401.
9. Protected endpoint with a valid token → 200.
10. Tamper tests → 401: expired token, token from another realm, token with a
    non-`yserious.com` email (once §7 layer 3 exists).
11. Groups: `/api/users/{email}/groups` returns groups for a real user.

---

## 9. Known POC gaps (do not ship as-is)

| Gap | Why it matters |
|---|---|
| Backend does not validate `aud` | Any token from the realm is accepted by this API. Keycloak's default `aud` is `account`. Add an Audience mapper and a validator. |
| Backend does not check email domain / `email_verified` | Relies entirely on Google/Keycloak settings. |
| `setAuthoritiesClaimName("realm_access.roles")` | I believe `JwtGrantedAuthoritiesConverter` does not resolve nested claims, so no authorities may be mapped. Replace with a converter that reads `realm_access` → `roles`. Not verified. |
| `/api/users/{email}/groups` trusts the email in the URL | Any authenticated user can request another user's groups. Use the JWT's `email` and ignore (or verify) the path value. |
| `identity_provider` shows blank | A User Session Note mapper was added but the claim did not appear; cosmetic. Derive it in the backend or fix the mapper scope. |
| Delegated admin is a personal account | If that user is removed or loses admin rights, groups break for everyone. Use a dedicated least-privilege service admin. |
| Hardcoded CORS origin `http://localhost:5173` | Move to configuration. |
| Service account key was pasted into a chat | **Rotate it** (IAM → Service Accounts → Keys). |

---

## 10. Production checklist

### Keycloak
- Run `start` (or `build` then `start --optimized`), not `start-dev`.
- **HTTPS everywhere.** Terminate TLS at a reverse proxy/load balancer and set
  `KC_PROXY=edge` (Keycloak 24), or give Keycloak a certificate directly.
- **Pin the hostname:** `KC_HOSTNAME_URL=https://sso.yserious.com` (not
  `KC_HOSTNAME=localhost` with strict checking off). The token `iss` must
  equal every backend's `issuer-uri` character for character.
- Replace `admin/admin` and `keycloak_pw`; inject from a secret manager.
- Set realm `sslRequired` to `all` (or `external` behind a proxy that
  forwards correctly), enable brute-force detection, and set short access-token
  lifespans (minutes).
- Managed Postgres with backups; Keycloak behind a load balancer for HA
  (shared DB, cache configuration per the Keycloak clustering docs).
- Keep realm configuration as code (export/partial import, or Terraform
  `keycloak` provider) with secrets excluded; don't hand-edit prod.
- Enable health/metrics (`KC_HEALTH_ENABLED`, `KC_METRICS_ENABLED`) and ship
  logs and events (login, login error) to monitoring.
- Lock down the admin console (separate hostname or network allow-list).

### Google Cloud / Workspace
- Add the production redirect URI
  `https://sso.yserious.com/realms/<realm>/broker/google-oidc/endpoint`.
  Keep dev and prod as **separate OAuth clients** (and ideally separate realms).
- Keep the consent screen **Internal**.
- Client secret in a vault; rotate on a schedule.
- Service account: dedicated least-privilege admin to impersonate, key stored
  outside the repo and artifact (`GOOGLE_SA_KEY_PATH` or workload identity /
  secret manager), rotated regularly, delegation scopes read-only.

### Backend(s)
- `issuer-uri` = the public HTTPS Keycloak realm URL.
- Add audience and email-domain validators (§9).
- Replace the roles converter; decide the authorization model (§11.3).
- Restrict CORS to the real frontend origin(s).
- Don't load secrets from the classpath; don't bake them into images.
- Keep the backend stateless (`SessionCreationPolicy.STATELESS`, already set).

### Frontend
- Exact redirect URIs and web origins in the Keycloak client (no wildcards in
  production), PKCE S256 enforced on the client.
- Guard `keycloak.init()` against double invocation (already done).
- Refresh tokens with `keycloak.updateToken()` before API calls instead of
  sending a stale `keycloak.token`.

---

## 11. Integrating into a real running project

### 11.1 Add SSO to an existing web app
1. In Keycloak create a **client per application** (public client + PKCE for
   SPAs; confidential client for server-rendered apps). Do not reuse the
   POC frontend client.
2. Add the app's exact redirect/logout URIs and web origins.
3. Use `keycloak-js` (SPA) or your framework's OIDC library (Spring
   `oauth2Login`, Next-Auth, etc.) against the realm's discovery URL.
4. Send users through `idpHint: 'google-oidc'` for domain-wide SSO, or set the
   **Identity Provider Redirector** (Authentication → browser flow → config →
   Default Identity Provider = `google-oidc`) so Keycloak skips its login page.

### 11.2 Protect existing APIs
1. Add `spring-boot-starter-oauth2-resource-server` (or your platform's JWT
   middleware) and set `issuer-uri`.
2. Give each API its own **audience**: create a Keycloak client scope with an
   Audience mapper (e.g. `aud=orders-api`) and validate it on that API.
3. Never accept tokens from the Google IdP directly; only Keycloak-issued ones.
4. Service-to-service calls should use client-credentials clients, not user tokens.

### 11.3 Authorization (roles and groups)
Authentication ("this is a `yserious.com` user") comes free from SSO.
Authorization needs a decision, because Google sends no groups in OIDC:

| Option | How | Trade-off |
|---|---|---|
| **A. Backend lookup (this POC)** | Service account + Directory API at request time | Needs domain-wide delegation; add a cache (groups change slowly) |
| **B. Map groups to Keycloak roles** | Sync/map Google groups to Keycloak groups/roles (script or custom mapper) so roles appear in the JWT | Roles ride in the token; sync lag and extra moving parts |
| **C. Cloud Identity Groups API with the user's own token** | Request `cloudidentity.groups.readonly` and call as the user | No domain-wide delegation; needs scope/consent changes |

Whichever you pick: map groups → application roles in one place, authorize on
roles (not raw group emails) inside the app, and cache lookups.

### 11.4 User lifecycle
- First login auto-creates the Keycloak user; set Trust Email and decide how
  to handle pre-existing local users with the same email (delete/migrate, or
  configure auto-link in the first-broker-login flow).
- **Offboarding:** disabling a user in Workspace blocks new Google logins, but
  existing Keycloak sessions and tokens live until they expire. Keep access
  tokens short, set SSO session idle/max limits, and disable/delete the
  Keycloak user for immediate cut-off.
- Logout: `keycloak.logout()` ends the Keycloak session only, not Google's.

### 11.5 Rollout plan
1. Stand up production Keycloak (HTTPS, pinned hostname, real secrets).
2. Create the production Google OAuth client with the production redirect URI.
3. Import the realm (without secrets), then set IdP secrets via the admin
   console or secret-backed automation.
4. Run the §8 checklist in staging with two real users plus a Gmail negative test.
5. Onboard one low-risk internal app first; add APIs and audiences one at a time.
6. Monitor login errors, token validation failures, and Directory API quota.

---

## 12. Troubleshooting quick reference

| Error | Likely cause |
|---|---|
| `redirect_uri_mismatch` (Google) | Redirect URI in Google ≠ Keycloak's IdP Redirect URI; or browsing via `127.0.0.1` |
| `access_denied` / "app not verified" | Consent screen is External/Testing, or user not in test list; switch to Internal |
| Keycloak "Invalid parameter: redirect_uri" | Frontend client redirect URIs / web origins don't match the SPA URL |
| Backend 401 on every call | `iss` mismatch (hostname/port/scheme), expired token, or missing `Authorization` header |
| Backend can't start / discovery fails | Keycloak unreachable at `issuer-uri` (e.g. backend in Docker using `localhost`) |
| Groups `invalid_grant` | Delegated admin email isn't a real user |
| Groups `unauthorized_client` | Domain-wide delegation not configured (wrong Client ID or scopes), or not yet propagated |
| Groups 403 | Delegated user isn't an admin, or Admin SDK API not enabled |
| "A 'Keycloak' instance can only be initialized once" | `init()` called twice (StrictMode); share one init promise |
