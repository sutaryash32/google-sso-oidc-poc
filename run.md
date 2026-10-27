# Run guide

Everyday use first, then first-time setup, then fixes for the things that go wrong. Paths are relative to this folder
(the one holding `google-oidc-poc-backend`, `google-oidc-poc-frontend` and `google-oidc-poc-keycloak`).

The login is **hub-and-spoke**: the app signs in to the tenant's own realm (`yserious`), which reaches Google through the shared
`master` realm. The shape and the reasons are in `google-oidc-poc-keycloak/README.md`.

## What runs

| Part | Port | How it starts |
|---|---|---|
| Keycloak (login, with the tenant plugin built in) | 8280 | Started for you by the backend (Docker) |
| Keycloak database (Postgres) | 5433 | same |
| Application database (Postgres, tenant-scoped data) | 5435 | same |
| Backend (Spring Boot API) | 8095 | You start it |
| Frontend (React app) | 5173 | You start it |

## Everyday run

1. **Start Docker Desktop** and wait until it says it is running.
2. **Start the backend**, either way:
   - IntelliJ: run `GoogleOidcPocApplication`, or
   - terminal:
     ```powershell
     cd google-oidc-poc-backend
     mvn spring-boot:run
     ```
   It starts Keycloak and both databases by itself and waits until they are healthy (about 45 seconds on a normal day).
   It is ready when you see `Started GoogleOidcPocApplication`.
3. **Start the frontend** in a second terminal:
   ```powershell
   cd google-oidc-poc-frontend
   npm run dev
   ```
4. Open **http://localhost:5173** and click **Sign in with Google Workspace**. You should see your tenant
   (`yserious.com (t-yserious)`), your identity (identity provider `google`) and your Google groups.

To sign in to **another tenant**, open "Sign in to a different organization" on the card, type the organization's domain (for example
`neelias.com`) and click Continue: the page finds that tenant's realm and signs you in to it. The registered tenants are the ones in
`google-oidc-poc-keycloak/tenant-registry.json` (`node scripts\tenant.mjs list`). While the Google consent screen is in *Testing* mode,
each account you try must be listed as a test user there.

If the page shows an error about an outdated session, click **Sign out and try again**, then sign in again.

### Stopping

- Stop the backend and the frontend with Ctrl+C (or the IDE stop button).
- The containers **keep running** after the backend stops, so the next start is fast. To stop them too:
  ```powershell
  cd google-oidc-poc-keycloak
  docker compose stop
  ```
- Nothing is lost by stopping. `docker compose down` also keeps your data. Only `docker compose down -v` wipes it (realms,
  users, application data), so avoid `-v` unless you mean to start from nothing.

## First-time setup (a new machine or a blank database)

You need: **Docker Desktop**, **JDK 17**, **Maven**, **Node.js 22** (with npm), and a Google OAuth client.

1. **Google OAuth client** (Google Cloud Console, APIs & Services, Credentials): type *Web application*, with this authorized
   redirect URI exactly, and no other is needed for tenants:
   `http://localhost:8280/realms/master/broker/google/endpoint`
   **Consent screen:** *Internal* admits only your own Workspace; other organizations can only reach this system if it is *External*
   (in *Testing* mode, add each account you will try as a test user). That is a separate decision, see "Adding another organization".
2. **Service account key for group lookups** (optional; without it only the groups section fails): put
   `google-service-account.json` in `google-oidc-poc-backend/src/main/resources/`. It is git-ignored. The service account needs
   domain-wide delegation with the two read-only Directory scopes in your Workspace Admin console.
3. **Start the backend once** (see Everyday run, step 2). The first start takes a few minutes: Docker builds the Keycloak image,
   which compiles the tenant plugin and runs its tests. The application database is created automatically.
4. **Create the tenant realm, the shared Google IdP and the gates** (needs Node; run from `google-oidc-poc-keycloak`):
   ```powershell
   $env:GOOGLE_CLIENT_ID = '<your OAuth client id>'
   $env:GOOGLE_CLIENT_SECRET = '<your OAuth client secret>'
   node scripts\setup-tenant.mjs --id yserious --domain yserious.com
   node scripts\setup-tenant.mjs --id yserious --check       # read-only: everything should say OK
   ```
   This builds, in one idempotent run: master's Google IdP, the broker client, realm `yserious` with its `google-hub` IdP, the
   **tenant gate** (refuses any sign-in whose Google `hd`, verified email and email domain are not `yserious.com`), the app client, and the
   **master gate**. Safe to run again. The registry entry for the tenant, with its issuer, is already in
   `google-oidc-poc-keycloak/tenant-registry.json`; the backend reads it.
5. **Install the frontend:** `cd google-oidc-poc-frontend`, then `npm install`.
6. Do the **Everyday run** and sign in once. That creates your user in `master` and in `yserious` and records your tenant.

The Google sign-in at the end needs your real Google client. The setup (steps 3 to 4) is exercised end to end, without Google, by
the test-harness suites below.

## Everyday tasks

**Tenants are not a Keycloak console object.** A tenant is a realm plus its gates (`setup-tenant.mjs`) plus an entry in the registry
(`tenant.mjs`, read by the backend). Changes to the registry apply to the backend at once, with no restart. From
`google-oidc-poc-keycloak`:
```powershell
node scripts\setup-tenant.mjs --id acme --domain acme.com [--domain acme.co.uk]
node scripts\tenant.mjs add --id t-acme --name "Acme Corp" --domain acme.com --issuer http://localhost:8280/realms/acme
node scripts\tenant.mjs list
node scripts\tenant.mjs suspend t-acme       # API 403 at once; also ends the tenant realm's sessions and its users' master sessions
node scripts\tenant.mjs activate t-acme
node scripts\setup-tenant.mjs --id acme --revert     # removes the realm and its broker client
```

**Check a tenant's wiring** (read-only; run it after any change to a realm, because a realm without its gate admits whatever master
admits): `node scripts\setup-tenant.mjs --id yserious --check`.

**See what happened after a sign-in attempt** (read-only): `node scripts\observe-tenant.mjs --id yserious`. It lists the users in
`master` and in the tenant realm, the domains each gate is bound to, and the recent gate decisions from the Keycloak log
(`TENANT_ALLOWED` / `TENANT_DENIED ... reason=...`). Run it before and after a test sign-in and compare.

**Master's Hosted Domain** is `*` now (any managed Google organization can reach Keycloak; consumer Gmail has no `hd` and is refused at
master). Change it only deliberately: `node scripts\setup-tenant.mjs --id yserious --domain yserious.com --hosted-domain yserious.com`
restricts it again.

**Adding another organization** needs three things the scripts cannot do for you: prove the customer owns the domain before you add
it, make sure the Google consent screen is *External* (and that their accounts may sign in: test users while in *Testing*), and (only
for group lookups) have their Workspace admin authorize your service account. Details are in `google-oidc-poc-keycloak/README.md`.

**Run the unit tests**
```powershell
cd google-oidc-poc-keycloak\tenant-spi ; mvn test          # the plugin: 46
cd ..\..\google-oidc-poc-backend ; mvn test                # the backend: 71
```
The backend's 11 database tests need the harness database (`$env:TENANT_DB_URL='jdbc:postgresql://localhost:5434/spike'` with the
harness up); without it they are skipped, not failed.

**The test harness** (a second, throwaway Keycloak with a fake Google, used for the security tests), from
`google-oidc-poc-keycloak\test-harness`:
```powershell
docker compose up -d --build spike-keycloak spike-db
node mock-idp\server.mjs                          # leave running, in its own terminal
node scripts\hub-and-spoke-e2e.mjs                # the chain and the tenant gate: 43 checks
node scripts\master-gate-e2e.mjs                  # the master gate with a Google-like IdP in master: 46
node scripts\e2e-backend-hub.mjs                  # the real backend against two realms, incl. a forging realm: 22 (needs Maven and Java)
docker compose down                               # when finished
```
Each suite sets up its own realms. The earlier single-realm suites (`setup-realm.mjs`, `e2e.mjs`, `e2e-attacks.mjs`, `e2e-backend.mjs`)
are described in `test-harness/README.md`.

**Look at the databases in pgAdmin** (development credentials only):

| | Host | Port | Database | User | Password |
|---|---|---|---|---|---|
| Keycloak | 127.0.0.1 | 5433 | `keycloak` | `keycloak` | `keycloak_pw` |
| Application | 127.0.0.1 | 5435 | `app` | `app_owner` | `owner_pw` |

**Keycloak admin console:** http://localhost:8280/admin, `admin` / `admin`. Look at realms `master` and `yserious`: Users, and under
Identity providers the `google` (master) and `google-hub` (`yserious`) IdPs with their mappers, including the gate.

**After changing the tenant plugin** (`google-oidc-poc-keycloak/tenant-spi`), rebuild or Keycloak keeps running the old one:
```powershell
cd google-oidc-poc-keycloak
docker compose build keycloak
docker compose up -d
```

## The earlier single-realm login (optional fallback)

The realm `google-oidc-poc` that brokers to Google directly still exists if it was created before. To use it: remove `"issuer"` from
the tenant's registry entry, start the backend with `TENANT_ISSUER=http://localhost:8280/realms/google-oidc-poc` and
`TENANT_JWK_SET_URI=http://localhost:8280/realms/google-oidc-poc/protocol/openid-connect/certs`, and the frontend with
`$env:VITE_KC_REALM='google-oidc-poc'; $env:VITE_KC_IDP_HINT='google-oidc'; npm run dev`. Its Google redirect URI is
`http://localhost:8280/realms/google-oidc-poc/broker/google-oidc/endpoint`; its setup script is `scripts\enable-multitenancy.mjs`.

## When something goes wrong

| Symptom | Cause and fix |
|---|---|
| Backend fails with a Docker error such as "cannot connect to the Docker daemon" | Docker Desktop is not running. Start it and run the backend again. |
| `Address already in use` on 8095 | Another backend is running. Stop it, or find it: `netstat -ano \| findstr :8095`, then `taskkill /PID <number> /F`. |
| `No Docker Compose file found` or `Tenant registry not found` | The backend could not locate the sibling `google-oidc-poc-keycloak` folder. It searches the working directory, three levels up, and one level down, so check the project layout is intact. As a last resort set `TENANT_REGISTRY_FILE` to the absolute path of `tenant-registry.json`. |
| First start seems stuck | Normal the first time (image build, a few minutes). Watch it with `docker compose logs -f keycloak` in `google-oidc-poc-keycloak`. |
| Google says `redirect_uri_mismatch` | Master's redirect URI is not on the OAuth client: add `http://localhost:8280/realms/master/broker/google/endpoint` in Google Cloud and wait a few minutes. |
| Keycloak shows "Invalid redirect uri" on logout | The broker client's post-logout URI is missing: run `node scripts\setup-tenant.mjs --id yserious --domain yserious.com` again. |
| Page shows 401 errors on `/api/...` (backend running) | The backend does not trust the token's issuer. Is the tenant's `"issuer"` in `tenant-registry.json` exactly the realm's URL, and was the backend restarted after the change? |
| API returns `403` with `issuer_mismatch` | The token comes from a realm that is not the one bound to the tenant it claims. Check the registry's `issuer` and the realm's constant claims. |
| Sign-in ends on a Keycloak "Access denied" or "Unexpected error ... identity provider" page | A gate refused the account (a personal Gmail, a domain that is not a tenant, an unverified email, or a different Google subject for a known user). The reason is in the log: `docker logs oidc-poc-keycloak 2>&1 \| findstr TENANT_` or `node scripts\observe-tenant.mjs --id yserious`. |
| Google box stays locked to `@yserious.com` | A stale sign-in page from before Hosted Domain was changed. Close every tab and start again from the app in a new incognito window. |
| Groups section shows an error | `google-service-account.json` is missing, or domain-wide delegation is not authorized. Everything else still works. |
| `Connection refused` to a database | The container is down: `docker compose up -d` in `google-oidc-poc-keycloak`. |
| pgAdmin: password authentication failed | Use `127.0.0.1` (not `localhost`) and the passwords in the table above. |
| Everything is gone after a reset | `docker compose down -v` wipes the data. Redo First-time setup from step 3. |

## Where to read more

- `google-oidc-poc-keycloak/README.md`: how a login works, the objects, adding tenants, tests and known gaps.
- `google-oidc-poc-keycloak/docs/hub_and_spoke_poc_plan.md`: the design and what changed since.
- `google-oidc-poc-keycloak/docs/google_hub_and_spoke_design.md`: how it maps onto SecuFusion's Azure implementation, with risks.
- `google-oidc-poc-keycloak/docs/architecture_validation.md`: a critical review of the earlier shared-realm design, kept as a record.
- [pitch.md](pitch.md): a short client-facing description.
