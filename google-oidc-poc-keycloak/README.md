# Multi-Tenant Google Workspace SSO (OIDC)

Keycloak is the identity broker, Google Workspace is the identity source, and a Spring Boot resource
server validates the Keycloak JWTs. **`yserious.com` is tenant #1**; other organizations are added by
registering them (see "Add a tenant"). The realm (`google-oidc-poc`) and client ids are unchanged.

The repository has exactly three project folders:

```
google-oidc-poc-keycloak/    (this folder) Keycloak 24.0.3 + app database (Docker), tenant registry, tenant scripts
  tenant-spi/                Keycloak plugin (Java) that resolves and enforces the tenant at login
  db/                        schema for the application database
  docs/                      design + guides
  test-harness/              mock Google + end-to-end suites
google-oidc-poc-backend/     Spring Boot: JWT + tenant validation, tenant-scoped data, Google Groups
google-oidc-poc-frontend/    React/Vite: login, shows the resolved tenant, identity and groups
```

Start with: `docs/multi_tenant_saas_design.md` (architecture and rationale), `docs/architecture_validation.md` (a critical
review of that design: what was tested, the weaknesses found, and the verdict), `docs/google_spike_runbook.md` (the real-Google
sign-ins only you can do, step by step), `test-harness/README.md` (what was
proven, how, and what was not) and `docs/sso_oidc_readme.md` (original single-domain POC guide: the Google/Keycloak
setup steps). All paths below are relative to this folder.

## How a login works

1. The SPA sends the user to Keycloak with `kc_idp_hint=google-oidc`; Keycloak sends them to Google
   (`hd=*`, `prompt=select_account`).
2. Google authenticates; Keycloak validates the ID token.
3. **Tenant enforcement** (the SPI, an identity-provider mapper) runs *before any Keycloak user is
   created*: the verified `hd` claim must resolve, through `tenant-registry.json`, to exactly one active,
   SSO-enabled tenant, and the email / discovery hint / existing user must agree with it. Otherwise: 403, no user, no token.
4. On success the user is stamped with admin-only attributes `tenant_id` and `tenant_domain`, and the
   tokens carry them as claims, plus the audience `oidc-poc-api`.
5. The backend validates signature, issuer, expiry, audience and tenant claims, re-checks the tenant
   against the registry **on every request**, and scopes every query to the token's tenant
   (explicit `tenant_id` filter + Postgres row-level security).

## Run order

**Starting the backend also starts everything it depends on.** Spring Boot's Docker Compose support runs this
folder's `docker-compose.yml` for you and waits until Keycloak and both databases are healthy, so there are only
two things to start:

```powershell
# 1. Backend (port 8095). Also starts Keycloak + its database + the application database.
cd ..\google-oidc-poc-backend
mvn spring-boot:run          # or run GoogleOidcPocApplication from your IDE; no profile or VM option needed

# 2. Frontend (port 5173), in another terminal
cd ..\google-oidc-poc-frontend
npm install ; npm run dev
```

Open http://localhost:5173 and sign in. You should see your tenant, identity and groups.

Things to know:

- **First start is slow (a few minutes).** Docker builds the Keycloak image, which includes compiling the tenant
  plugin and running its unit tests, and downloads the base images. Later starts take well under a minute.
- **The containers keep running when the backend stops** (`lifecycle-management: start-only`), so a restart is fast.
  Stop them with `docker compose stop` in this folder.
- **After changing `tenant-spi/`**, rebuild the image or Keycloak keeps the old plugin: `docker compose build keycloak`,
  then `docker compose up -d`.
- **Group lookups** need `google-service-account.json` in `google-oidc-poc-backend/src/main/resources/`.
- **To start the containers yourself instead** (or in production, where the backend must not start infrastructure),
  run `docker compose up -d --build` here and start the backend with `SPRING_DOCKER_COMPOSE_ENABLED=false`.
- **One-time realm setup.** `node scripts\enable-multitenancy.mjs` has already been applied to your realm. It is
  idempotent; re-run it only for a fresh Keycloak database (`--revert` undoes it). See "What the script changes".

## Add a tenant

```powershell
node scripts\tenant.mjs add --id t-acme --name "Acme Corp" --domain acme.com [--domain acme.co.uk] [--groups-admin admin@acme.com] [--sso off]
node scripts\tenant.mjs list
node scripts\tenant.mjs suspend t-acme       # new logins denied, API returns 403 immediately
node scripts\tenant.mjs activate t-acme
node scripts\tenant.mjs add-domain t-acme acme.org
```

The Keycloak SPI and the backend both reload the registry file when it changes: no restart. The CLI refuses a
domain that already belongs to another tenant (an ambiguous registry is denied at login), an invalid id or
domain, and a groups admin outside the tenant's own domains.

**Before a real customer can sign in, three things are NOT automated:**

1. **Domain ownership.** Prove the customer owns the domain (e.g. a DNS TXT challenge) *before* adding it. The
   registry decides who may sign in, and `hd` only proves membership of a Workspace, not authority over a domain.
2. **Google consent screen.** It is currently **Internal**, which admits only your own organization. Accounts
   from other organizations never reach Keycloak until the OAuth consent screen is **External** and published
   (Google Cloud Console). That is a manual step in Google; nothing in this repo can do it.
3. **Group sync for that tenant** (optional). `--groups-admin` must be a real admin in *their* Workspace, and
   their super admin must authorize the service account's Client ID (domain-wide delegation) with the read-only
   Directory scopes in *their* Admin console. Without it, `/api/users/{email}/groups` returns 501 for that tenant.

## What `enable-multitenancy.mjs` changes in the realm

- Google IdP `google-oidc`: Hosted Domain `yserious.com` → `*` (the registry, not Hosted Domain, is now the
  tenant boundary; consumer Gmail is still rejected because `*` requires an `hd` claim); `prompt=select_account`.
- Adds the `tenant-resolver` identity-provider mapper (the SPI).
- Adds admin-only user attributes `tenant_id`, `tenant_domain`, `idp_alias`, `idp_subject`; back-fills them for existing Google-linked users.
- On client `google-oidc-poc-frontend` (id unchanged): `tenant_id`, `tenant_domain`, `idp`, `idp_sub` and audience mappers. `idp` / `idp_sub` are the identity provider and ITS subject for the person (for Google, the `sub` claim): the stable person key. Keycloak's own user id is not stable (it changes if the user is deleted and re-linked), so the backend keys users on `(tenant_id, idp, idp_sub)`.
- With `--harden` (validated on the test harness, not yet applied to this realm): a first-login flow that **never links a new Google identity to an existing user by email**, and a **token-time tenant guard** that refuses tokens, including refreshes, for a suspended tenant.

The Google client id/secret, the realm name, existing users and the client ids are not touched.

## Ports

| Service | Port |
|---|---|
| Keycloak | 8280 |
| Backend | 8095 |
| Frontend | 5173 |
| Keycloak DB (pgAdmin) | 5433 |
| Application DB (backend, pgAdmin) | 5435 |

The test harness (`test-harness/`) uses its own Keycloak (8380), database (5434) and mock IdP (9100).

## Tests

```powershell
cd ..\google-oidc-poc-backend ; mvn test    # 39 tests; the 11 database tests need the harness database up (see below)
cd ..\google-oidc-poc-keycloak\test-harness
docker compose up -d                         # spike Keycloak + spike database
node mock-idp\server.mjs                     # mock Google, leave running
node scripts\setup-realm.mjs ; node scripts\e2e.mjs                 # SPI: 20 scenarios
# backend e2e: see test-harness\README.md ("Backend enforcement")
```

The database tests are destructive (they truncate the tenant tables), so they refuse to run against anything
other than the disposable spike database unless `ALLOW_DESTRUCTIVE_DB_TESTS=true`.

## Known gaps

- **Not verified with a real Google login in this configuration.** The SPI was proven against a mock Google
  (and the realm, tokens, backend, database and groups were verified with a token for your real user), but the
  first genuine sign-in through Google with `hd=*` and the SPI is yours to run.
- **Roles / permissions are not implemented** (the token's authorities are empty); only tenant isolation is.
- Domain-ownership verification, a tenant control-plane API (the registry is a JSON file), alias/secondary-domain
  behaviour of `hd`, and multi-tenant domain-wide-delegation onboarding are still design (see
  `docs/multi_tenant_saas_design.md`).
- Dev credentials are in `docker-compose.yml` (`admin/admin`, database passwords). The service-account key was
  pasted into a chat earlier; rotate it.
