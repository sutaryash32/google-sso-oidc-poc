# Run guide

Everyday use first, then first-time setup, then fixes for the things that go wrong. Paths are relative to this folder
(the one holding `google-oidc-poc-backend`, `google-oidc-poc-frontend` and `google-oidc-poc-keycloak`).

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
4. Open **http://localhost:5173** and click **Sign in with Google Workspace**. You should see your tenant, your identity and
   your Google groups.

If the page shows an error about an outdated session, click **Sign out and try again**, then sign in again.

### Stopping

- Stop the backend and the frontend with Ctrl+C (or the IDE stop button).
- The containers **keep running** after the backend stops, so the next start is fast. To stop them too:
  ```powershell
  cd google-oidc-poc-keycloak
  docker compose stop
  ```
- Nothing is lost by stopping. `docker compose down` also keeps your data. Only `docker compose down -v` wipes it (realm,
  users, application data), so avoid `-v` unless you mean to start from nothing.

## First-time setup (a new machine or a blank database)

You need: **Docker Desktop**, **JDK 17**, **Maven**, **Node.js 22** (with npm), and a Google OAuth client.

1. **Google OAuth client** (Google Cloud Console, APIs & Services, Credentials): type *Web application*, with this authorized
   redirect URI exactly:
   `http://localhost:8280/realms/google-oidc-poc/broker/google-oidc/endpoint`
   Keep the consent screen *Internal* to admit only your own Workspace. Anyone outside it can only reach this system if it is
   *External*, which is a separate decision (see "Adding another organization").
2. **Service account key for group lookups** (optional; without it only the groups section fails): put
   `google-service-account.json` in `google-oidc-poc-backend/src/main/resources/`. It is git-ignored. The service account needs
   domain-wide delegation with the two read-only Directory scopes in your Workspace Admin console.
3. **Start the backend once** (see Everyday run, step 2). The first start takes a few minutes: Docker builds the Keycloak image,
   which compiles the tenant plugin and runs its tests. The application database is created automatically.
4. **Create the realm.** Open http://localhost:8280/admin (login `admin` / `admin`), then realm dropdown -> *Create realm* ->
   browse to `google-oidc-poc-keycloak/realm-google-oidc-poc.json` -> name `google-oidc-poc` -> *Create*.
5. **Give Keycloak the Google credentials:** Identity providers -> `google-oidc` -> paste the **Client ID** and **Client Secret**
   from step 1 -> Save. (The imported file only has placeholders.)
6. **Apply the tenant configuration** (needs Node):
   ```powershell
   cd google-oidc-poc-keycloak
   node scripts\enable-multitenancy.mjs
   ```
   It is safe to run again. It sets Hosted Domain to `*`, adds the tenant plugin to the Google login, the tenant and
   provider-identity claims, and the audience. Add `--harden` to also apply the two protections described in
   `docs/architecture_validation.md` (no linking of accounts by email, and no tokens for a suspended tenant); they are tested but
   **not applied to the current real realm yet**.
7. **Install the frontend:** `cd google-oidc-poc-frontend`, then `npm install`.
8. Do the **Everyday run** and sign in once. That creates your Keycloak user and records your tenant.

Steps 4 to 6 were run end to end on a blank Keycloak while writing this guide; the Google sign-in at the end needs your real
Google client, so it was not run.

## Everyday tasks

**See or change tenants** (from `google-oidc-poc-keycloak`; changes apply immediately, no restart):
```powershell
node scripts\tenant.mjs list
node scripts\tenant.mjs add --id t-acme --name "Acme Corp" --domain acme.com
node scripts\tenant.mjs suspend t-acme       # blocks new logins and API calls, and ends the tenant's sessions
node scripts\tenant.mjs activate t-acme
```

**Check that the tenant setup is in place** (read-only, changes nothing, hides secrets; run from `google-oidc-poc-keycloak`):
```powershell
node scripts\check-multitenancy.mjs
```
It prints OK or MISSING for each setting. The same things can be seen by hand in the Keycloak admin console
(http://localhost:8280/admin, realm `google-oidc-poc`): Identity providers -> `google-oidc` (Hosted Domain, attached mapper),
Realm settings -> User profile (the four tenant attributes), Clients -> `google-oidc-poc-frontend` -> Client scopes ->
`google-oidc-poc-frontend-dedicated` (claim mappers), and Users -> a user -> Attributes.

**Adding another organization** needs three things the scripts cannot do for you: prove the customer owns the domain before you add
it, switch the Google consent screen to *External*, and (only for group lookups) have their Workspace admin authorize your
service account. Details are in `google-oidc-poc-keycloak/README.md`.

**Run the tests**
```powershell
cd google-oidc-poc-backend
mvn test
```
The 11 database tests need the test harness database (below); without it they are skipped, not failed.

**The test harness** (a second, throwaway Keycloak with a fake Google, used for the security tests):
```powershell
cd google-oidc-poc-keycloak\test-harness
docker compose up -d --build
node mock-idp\server.mjs                 # leave running
node scripts\setup-realm.mjs
node scripts\e2e.mjs                     # tenant enforcement scenarios
node scripts\e2e-attacks.mjs             # abuse and identity-lifecycle cases
docker compose down                      # when finished
```

**Look at the databases in pgAdmin** (development credentials only):

| | Host | Port | Database | User | Password |
|---|---|---|---|---|---|
| Keycloak | localhost | 5433 | `keycloak` | `keycloak` | `keycloak_pw` |
| Application | localhost | 5435 | `app` | `app_owner` | `owner_pw` |

**Keycloak admin console:** http://localhost:8280/admin, `admin` / `admin`.

**After changing the tenant plugin** (`google-oidc-poc-keycloak/tenant-spi`), rebuild or Keycloak keeps running the old one:
```powershell
cd google-oidc-poc-keycloak
docker compose build keycloak
docker compose up -d
```

## When something goes wrong

| Symptom | Cause and fix |
|---|---|
| Backend fails with a Docker error such as "cannot connect to the Docker daemon" | Docker Desktop is not running. Start it and run the backend again. |
| `Address already in use` on 8095 | Another backend is running. Stop it, or find it: `netstat -ano \| findstr :8095`, then `taskkill /PID <number> /F`. |
| `No Docker Compose file found` or `Tenant registry not found` | The backend could not locate the sibling `google-oidc-poc-keycloak` folder. It searches the working directory, three levels up, and one level down, so check the project layout is intact. As a last resort set `TENANT_REGISTRY_FILE` to the absolute path of `tenant-registry.json`. |
| First start seems stuck | Normal the first time (image build, a few minutes). Watch it with `docker compose logs -f keycloak` in `google-oidc-poc-keycloak`. |
| Page says "Your session may be outdated" or the API returns 401 | The token predates a realm change. Click **Sign out and try again**. |
| Sign-in ends on a Keycloak "Access denied" page | The account was refused by the tenant check: a personal Gmail, a domain that is not registered, a suspended tenant, or a recreated account. The reason is in the Keycloak log: `docker logs oidc-poc-keycloak 2>&1 \| findstr TENANT_`. |
| Groups section shows an error | `google-service-account.json` is missing, or domain-wide delegation is not authorized. Everything else still works. |
| `Connection refused` to a database | The container is down: `docker compose up -d` in `google-oidc-poc-keycloak`. |
| Everything is gone after a reset | `docker compose down -v` wipes the data. Redo First-time setup from step 4. |

## Where to read more

- `google-oidc-poc-keycloak/README.md`: how a login works and how tenants are managed.
- `google-oidc-poc-keycloak/docs/multi_tenant_saas_design.md`: the architecture.
- `google-oidc-poc-keycloak/docs/architecture_validation.md`: a critical review, what was tested, what is still open.
- `google-oidc-poc-keycloak/docs/google_spike_runbook.md`: the real-Google sign-in checks that still need your accounts.
