# google-oidc-poc-backend

Spring Boot resource server (port 8095). It validates the tokens of each tenant's Keycloak realm, trusts each realm only for its
own tenant, and scopes all data to the caller's tenant. Package `com.secufusion.oidcpoc`; the multi-tenant code is in `tenant/`.

## What it enforces, in order

1. **Which issuers are trusted** (`TenantIssuerResolver`): the `issuer` of every tenant in the registry file
   (`../google-oidc-poc-keycloak/tenant-registry.json`), plus, optionally, one legacy issuer (`TENANT_ISSUER` /
   `TENANT_JWK_SET_URI`). Keys come from `<issuer>/protocol/openid-connect/certs`. An issuer nobody registered is never contacted and
   its tokens get 401. The registry is consulted on every request, so a removed tenant's realm stops being accepted at once.
2. **The token itself**: signature (that realm's keys), issuer, expiry, audience `oidc-poc-api`, and the presence of `tenant_id`,
   `tenant_domain`, `idp`, `idp_sub`, `sub`.
3. **Per request, in `TenantContextFilter`**: the tenant must exist in the registry, own the token's `tenant_domain`, be active and
   SSO-enabled, and the token's issuer must be the one bound to that tenant. A realm that writes another tenant's id into its tokens
   gets `403 issuer_mismatch`: the claim is written by whoever administers the realm, so it is not trusted alone.
4. **Data**: every query goes through `TenantTx`, which binds the tenant id in the transaction; Postgres row-level security
   (`FORCE`, non-owner role) enforces it. The person key is `(tenant, provider, provider subject)` (`idp_sub`, Google's `sub`),
   never the Keycloak user id.

Groups (`/api/users/{email}/groups`): read on demand from the Google Directory API by impersonating the tenant's
`groupsDelegatedAdmin` (from the registry) with one service account (domain-wide delegation). The email must be the caller's own and the
admin must belong to the tenant's domains. Authorities in the token are empty: roles are not implemented.

## Configuration (`src/main/resources/application.yml`, all overridable by environment)

| Key | Default | Meaning |
|---|---|---|
| `app.tenant.registry-file` (`TENANT_REGISTRY_FILE`) | `google-oidc-poc-keycloak/tenant-registry.json` | tenants, domains, issuers, groups admin; searched from the working directory, three parents up and one level down |
| `app.tenant.issuer` / `jwk-set-uri` (`TENANT_ISSUER`, `TENANT_JWK_SET_URI`) | empty | optional single legacy issuer (the earlier one-realm design, and the test harness). A tenant that has an `issuer` in the registry is never served from it |
| `app.tenant.audience` (`TENANT_AUDIENCE`) | `oidc-poc-api` | required audience |
| `app.tenant.datasource.*` (`TENANT_DB_URL`, `_USER`, `_PASSWORD`) | `localhost:5435/app`, `app_user` | application database; the role must not be the owner or a superuser, or RLS is bypassed |
| `google.workspace.service-account-key-path` (`GOOGLE_SA_KEY_PATH`) | `classpath:google-service-account.json` | service-account key for groups; git-ignored |
| `SPRING_DOCKER_COMPOSE_ENABLED` | on | start the Keycloak/database containers with the backend (`start-only`); turn off for production and tests |

## Run and test

```powershell
mvn spring-boot:run          # also starts Keycloak and both databases (Docker Compose support); first start takes minutes
mvn test                     # 71 tests; the 11 database tests need the harness database (set TENANT_DB_URL=jdbc:postgresql://localhost:5434/spike)
```

The database tests truncate tables, so they refuse any database but the disposable `spike` one unless `ALLOW_DESTRUCTIVE_DB_TESTS=true`.
The end-to-end suite that runs this backend against two real realms is
`../google-oidc-poc-keycloak/test-harness/scripts/e2e-backend-hub.mjs` (it builds and starts the jar itself).

Changing the issuer or registry needs no code change; a code change needs a restart. The JVM time zone is pinned to UTC (some Postgres
images reject legacy names such as `Asia/Calcutta`).
