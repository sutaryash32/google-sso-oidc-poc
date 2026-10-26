# google-sso-oidc-poc

Multi-tenant Google Workspace single sign-on over OIDC, built as a **hub-and-spoke** federation that mirrors SecuFusion's Azure SSO:
every tenant has its own Keycloak realm (and issuer), one shared Google identity provider lives in the `master` realm, and each tenant
realm reaches it through a `google-hub` IdP. A Spring Boot resource server validates each tenant realm's tokens, trusts each issuer only
for its own tenant, and scopes all data to the caller's tenant. `yserious.com` is the first tenant.

```
Browser -> tenant realm (yserious) -> google-hub -> master realm -> shared Google IdP -> Google Workspace
                  JWT issued here        tenant gate               master gate
```

| Folder | What it is |
|---|---|
| [`google-oidc-poc-keycloak/`](google-oidc-poc-keycloak/README.md) | Keycloak (Docker) and its databases, the tenant plugin with the tenant gate (`tenant-spi/`), the tenant registry, the setup scripts, the design and review documents (`docs/`), and a test harness with a mock Google |
| [`google-oidc-poc-backend/`](google-oidc-poc-backend/README.md) | Spring Boot API: per-realm token validation, tenant-scoped data (Postgres row-level security), Google Groups |
| [`google-oidc-poc-frontend/`](google-oidc-poc-frontend/README.md) | React app: sign-in, the resolved tenant, identity and groups |

- **Run it:** [run.md](run.md).
- **Client-facing summary:** [pitch.md](pitch.md).
- **Understand it:** [`google-oidc-poc-keycloak/README.md`](google-oidc-poc-keycloak/README.md), then
  [`docs/hub_and_spoke_poc_plan.md`](google-oidc-poc-keycloak/docs/hub_and_spoke_poc_plan.md) (the design and its updates) and
  [`docs/google_hub_and_spoke_design.md`](google-oidc-poc-keycloak/docs/google_hub_and_spoke_design.md) (how it maps onto the Azure
  implementation, with risks). The earlier shared-realm design is kept as a record in the other documents under `docs/`.

Tenants are not created in the Keycloak console: `google-oidc-poc-keycloak/scripts/setup-tenant.mjs` builds the realm and its gates, and
`tenant.mjs` maintains the registry the backend reads.

**Status.** Proven with real Google: a `yserious.com` sign-in through every layer, and a personal Gmail refused with no user created.
Proven with a mock Google (automated suites): a second tenant, cross-tenant and foreign-organization refusals at master and at the
realm, a realm that forges another tenant's id refused by the backend, and tenant removal taking effect at once. **Not yet run with real
Google:** a foreign Workspace organization. See the known gaps in the Keycloak README.

This is a proof of concept. It contains **development-only credentials** (for example `admin` / `admin` and local database passwords in
the Docker Compose files). It does not contain Google credentials: the Google OAuth client secret and the service-account key
(`google-service-account.json`) are supplied locally and are git-ignored.
