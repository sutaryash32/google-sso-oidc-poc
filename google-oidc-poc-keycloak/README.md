# Multi-Tenant Google Workspace SSO (OIDC), hub-and-spoke

Keycloak is the identity broker, Google Workspace is the identity source, and a Spring Boot resource server validates the
tokens. The design mirrors SecuFusion's Azure SSO: **a realm per tenant, a shared Google identity provider in the `master`
realm, and a hub IdP in each tenant realm that reaches it.** `yserious.com` is the first tenant (realm `yserious`).

```
Browser / SPA
   |  kc_idp_hint=google-hub
   v
tenant realm  yserious     issues the app JWT   (iss = .../realms/yserious)
   |  IdP "google-hub"     (an OIDC client of master)      + TENANT GATE (yserious.com)
   v
realm  master              client "broker-for-yserious"
   |  IdP "google"         the ONE shared Google IdP        + MASTER GATE (all tenants' domains)
   v
Google Workspace
```

The repository has three project folders, and nothing else is needed:

```
google-oidc-poc-keycloak/    (this folder) Keycloak 24.0.3 + app database (Docker), tenant registry, setup scripts
  tenant-spi/                Keycloak plugin (Java): the tenant gate, plus the earlier single-realm tenant mapper
  db/                        schema for the application database
  docs/                      design and review documents
  scripts/                   setup-tenant.mjs, tenant.mjs, observe-tenant.mjs, ... (see "Scripts")
  test-harness/              mock Google and the end-to-end suites
google-oidc-poc-backend/     Spring Boot: per-realm token validation, tenant-scoped data, Google Groups
google-oidc-poc-frontend/    React/Vite: login, shows the resolved tenant, identity and groups
```

Where to read: [../run.md](../run.md) to run it; `docs/hub_and_spoke_poc_plan.md` for the design and what changed since;
`docs/google_hub_and_spoke_design.md` for how it maps onto SecuFusion's Azure implementation (and its risks); `test-harness/README.md`
for what was proven and how. The earlier shared-realm design is kept as a record in `docs/multi_tenant_saas_design.md`,
`docs/architecture_validation.md` and `docs/sso_oidc_readme.md`; it still runs as a fallback and is described at the end.

## How a login works

1. The SPA starts a login in the tenant realm (`yserious`) with the hint `google-hub`.
2. `google-hub` sends the browser to master (`kc_idp_hint=google`, client `broker-for-yserious`); master sends it to Google
   (`hd=*`, `prompt=select_account`).
3. Google authenticates. **Master gate:** before any user exists in master, the account's Google `hd`, verified email and email
   domain must belong to a domain of some tenant. An organization that is nobody's tenant is refused here and leaves no record.
4. Master maps `hd`, `sub` and `email_verified` onto the master user and hands the realm a token with `google_hd`, `google_sub`,
   `google_email_verified`. (Server-to-server calls from the tenant realm to master use the Docker-internal URL.)
5. **Tenant gate:** in the tenant realm, before any user exists there, the same three checks run against **that tenant's** domains.
   A real tenant's account sent to the wrong tenant's realm is refused here (master keeps a record for that person, since it
   belongs to its own tenant). Every missing claim is a denial.
6. The realm creates/links the user, stamps `google_hd` / `google_sub` (admin-only attributes) and issues **its own** JWT:
   `iss` = the tenant realm, `idp_sub` = the person's Google subject (the stable key; Keycloak's own user id is not),
   audience `oidc-poc-api`, and `tenant_id` / `tenant_domain` / `idp` as constants of the realm.
7. The backend accepts a token only if its issuer is the one the registry binds to a tenant, verifies signature, expiry and
   audience with that realm's keys, and then checks that the tenant claimed in the token is the tenant bound to that issuer
   (`403 issuer_mismatch` otherwise: whoever administers a realm can write any `tenant_id` into its tokens, so the claim alone is
   not trusted). It re-checks the tenant against the registry on every request, and scopes every query to it (explicit
   `tenant_id` filter plus Postgres row-level security).

Logout is federated: ending the tenant realm's session also ends master's (the broker client allows the return URI).

## Keycloak objects

| Where | Object |
|---|---|
| master (once) | IdP `google` (provider `google`, the Google OAuth client, Hosted Domain, `prompt=select_account`), its attribute importers (`hd`, `sub`, `email_verified`), the **master gate** |
| master (per tenant) | confidential client `broker-for-<id>`; redirect URI = the tenant realm's `google-hub` callback; post-logout URI; mappers that put `google_hd` / `google_sub` / `google_email_verified` into its tokens |
| tenant realm | IdP `google-hub` (`keycloak-oidc`, `trustEmail=false`, no userinfo call, issuer left blank), its three attribute importers, the **tenant gate**, client `google-oidc-poc-frontend` (PKCE S256, audience mapper, `idp_sub` and the constant claims), the three admin-only user attributes |

Tenants are **not** created in the admin console: use the scripts. The console is only for looking (a tenant's users appear
under Users with `google_hd` and `google_sub`, and the same person also exists in `master`).

## Add a tenant

Two commands: the realm and its gates, then its place in the registry, which the backend reads (the issuer is the realm's URL).

```powershell
node scripts\setup-tenant.mjs --id acme --domain acme.com [--domain acme.co.uk]      # secondary domains: repeat --domain
node scripts\tenant.mjs add --id t-acme --name "Acme Corp" --domain acme.com --issuer http://localhost:8280/realms/acme
node scripts\setup-tenant.mjs --id acme --check        # read-only: is everything in place? (exit 1 if not)
```

`setup-tenant.mjs` is idempotent. It also recomputes the master gate's domain list from the tenant realms, so it never goes stale.
The first run needs `$env:GOOGLE_CLIENT_SECRET` while master's Google IdP does not exist yet. Registry changes (suspend, activate,
remove) take effect on the backend's next request, with no restart:

```powershell
node scripts\tenant.mjs list
node scripts\tenant.mjs suspend t-acme       # API 403 at once; ends the tenant realm's sessions and its users' master sessions (session part untested)
node scripts\tenant.mjs activate t-acme
node scripts\tenant.mjs add-domain t-acme acme.org
node scripts\tenant.mjs set-issuer t-acme http://localhost:8280/realms/acme
node scripts\setup-tenant.mjs --id acme --revert      # removes the realm and its broker client (--all: master's Google IdP too)
```

**Hosted Domain.** Master's Google IdP is currently `*` (any managed Google organization may reach Keycloak; consumer Gmail has no
`hd` and is refused). The first tenant's setup creates it restricted to that tenant's domain; `--hosted-domain '*'` changes it.
The gates, not this setting, keep tenants apart: a realm without its gate admits whatever master admits, hence `--check`.

**Before a real customer can sign in, three things are NOT automated:**

1. **Domain ownership.** Prove the customer owns the domain (for example a DNS TXT challenge) before adding it. `hd` proves
   membership of a Workspace, not authority over a domain name.
2. **Google consent screen.** It must be **External** for other organizations to reach Keycloak. For this project it is External in
   *Testing* mode, which admits only the listed test users; publishing it admits any Google account (the gates still apply).
3. **Group sync for that tenant** (optional). `groupsDelegatedAdmin` must be a real admin of *their* Workspace, and their super
   admin must authorize the service account's Client ID with the read-only Directory scopes. Otherwise `/api/users/{email}/groups`
   returns 501 for that tenant.

## Groups

Groups are not Keycloak groups and are not in the token. They stay in each tenant's own Google Workspace and are read on demand: the
backend takes the tenant from the token, looks up that tenant's `groupsDelegatedAdmin` in the registry, and impersonates that admin
(domain-wide delegation, one service account for all tenants) to call the Google Directory API. Guards: the path email must equal the
token email, and the delegated admin's domain must belong to the tenant. Groups do not drive authorization yet (the token's
authorities are empty); if they are later mapped to roles or claims, namespace them by tenant.

## Run order

**Starting the backend also starts everything it depends on.** Spring Boot's Docker Compose support runs this folder's
`docker-compose.yml` and waits until Keycloak and both databases are healthy:

```powershell
cd ..\google-oidc-poc-backend ; mvn spring-boot:run     # port 8095; or run GoogleOidcPocApplication from the IDE
cd ..\google-oidc-poc-frontend ; npm install ; npm run dev   # port 5173, in another terminal
```

Open http://localhost:5173 and sign in. First-time realm setup and troubleshooting are in [../run.md](../run.md).

- **First start is slow (a few minutes):** Docker builds the Keycloak image, compiling the plugin and running its tests.
- **The containers keep running when the backend stops** (`start-only`); stop them with `docker compose stop` here.
- **After changing `tenant-spi/`**, rebuild or Keycloak keeps the old plugin: `docker compose build keycloak`, then `docker compose up -d`.
- **Group lookups** need `google-service-account.json` in `google-oidc-poc-backend/src/main/resources/` (git-ignored).
- **Without Spring starting Docker** (production): `docker compose up -d --build` here, and `SPRING_DOCKER_COMPOSE_ENABLED=false`.

## Scripts

| Script | What it does |
|---|---|
| `scripts/setup-tenant.mjs` | Sets up the shared hub (once) and one tenant: realm, `google-hub`, tenant gate, broker client, app client, master gate. `--check`, `--revert`, `--hosted-domain` |
| `scripts/tenant.mjs` | The tenant registry (`tenant-registry.json`): add, list, suspend, activate, add-domain, set-issuer |
| `scripts/observe-tenant.mjs` | Read-only snapshot: users in master and a tenant realm, the gates' bound domains, recent gate decisions from the log. Run before and after a sign-in test |
| `scripts/enable-multitenancy.mjs`, `check-multitenancy.mjs`, `migrate-provider-subject.mjs` | The earlier single-realm design (below) |

## Ports

| Service | Port |
|---|---|
| Keycloak | 8280 |
| Backend | 8095 |
| Frontend | 5173 |
| Keycloak DB (pgAdmin) | 5433 |
| Application DB (backend, pgAdmin) | 5435 |

The test harness uses its own Keycloak (8380), database (5434), mock IdP (9100) and, for one suite, a backend on 8196.

## Tests

Unit tests: `mvn test` in `tenant-spi/` (46) and in `../google-oidc-poc-backend` (71; the 11 database tests need the harness
database and refuse to touch any other, unless `ALLOW_DESTRUCTIVE_DB_TESTS=true`). End-to-end suites, without Google, in
`test-harness/scripts/` (each sets up its own realms; see `test-harness/README.md`):

| Suite | Proves |
|---|---|
| `hub-and-spoke-e2e.mjs` (43) | the chain, the tenant gate, a second tenant, cross-tenant refusals, each denial reason, federated logout, and a control showing a realm without its gate admits anyone |
| `master-gate-e2e.mjs` (46) | the master gate with a Google-like IdP in master: foreign organizations, consumer accounts, unverified emails and look-alike domains are refused at master with nothing created; removing a tenant narrows master |
| `e2e-backend-hub.mjs` (22) | the real backend against two realms: each realm only for its own tenant, a forging realm refused, an unregistered issuer never trusted, registry changes at once, data isolation |

With **real Google**: the `yserious.com` sign-in passes through every layer, and a personal Gmail is refused at master with no user
created. **Not yet run with real Google:** a foreign Workspace organization.

## Known gaps

- A foreign managed Google account has not been tried against real Google (needs a second Workspace); that denial is proven with the mock.
- **Roles / permissions are not implemented**; only tenant isolation is. Domain-ownership verification and a tenant control-plane API
  (the registry is a JSON file) are design only.
- The tenant claims in the app token are constants of the realm rather than derived from the issuer. Tenants are created by script
  (`setup-tenant.mjs` + `tenant.mjs`), not by an API; an admin endpoint that creates a tenant (realm, gates, registry entry) is not built.
  The sign-in page chooses the realm by the organization's domain (`/api/public/tenant`), which reveals only whether a domain is a
  serviceable tenant.
- PKCE is on between the app and the tenant realm; it is not enabled on the tenant-realm-to-master or master-to-Google legs.
- Master keeps a record for a real tenant's account sent to the wrong tenant's realm. The realm's `email_verified` flag stays false
  (the gate uses Google's own value, carried separately).
- Dev credentials are in `docker-compose.yml` (`admin/admin`, database passwords). The Google service-account key and the OAuth
  client secret were pasted into a chat during development: **rotate both**.

## The earlier single-realm design (still runs as a fallback)

All tenants shared one realm `google-oidc-poc` and one Google IdP `google-oidc-poc`/`google-oidc`; a plugin mapper
(`TenantResolverMapper`) resolved the tenant from `hd` through `tenant-registry.json` before user creation, and the backend
validated one issuer. Scripts: `enable-multitenancy.mjs` (`--harden`, `--revert`), `check-multitenancy.mjs`. To use it again, remove
`"issuer"` from the tenant's registry entry, start the backend with `TENANT_ISSUER` / `TENANT_JWK_SET_URI` pointing at that realm and
the frontend with `VITE_KC_REALM=google-oidc-poc` and `VITE_KC_IDP_HINT=google-oidc`. Its design and review are in
`docs/multi_tenant_saas_design.md` and `docs/architecture_validation.md`.
