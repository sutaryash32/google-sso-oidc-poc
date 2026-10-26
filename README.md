# google-sso-oidc-poc

Multi-tenant Google Workspace single sign-on over OIDC: Keycloak is the identity broker, Google Workspace is the identity
source, and a Spring Boot resource server validates the Keycloak tokens and scopes all data to the caller's tenant.
`yserious.com` is tenant #1; other organizations are added through a tenant registry.

| Folder | What it is |
|---|---|
| `google-oidc-poc-keycloak/` | Keycloak (Docker) and its databases, the tenant plugin (`tenant-spi/`), the tenant registry and scripts, the design and review documents (`docs/`), and a test harness with a mock Google |
| `google-oidc-poc-backend/` | Spring Boot API: token and tenant validation, tenant-scoped data (Postgres row-level security), Google Groups |
| `google-oidc-poc-frontend/` | React app: sign-in, the resolved tenant, identity and groups |

**To run it, read [run.md](run.md).** To understand it, start with
[`google-oidc-poc-keycloak/README.md`](google-oidc-poc-keycloak/README.md) and
[`docs/architecture_validation.md`](google-oidc-poc-keycloak/docs/architecture_validation.md).

This is a proof of concept. It contains **development-only credentials** (for example `admin` / `admin` and local database
passwords in the Docker Compose files). It does not contain Google credentials: the Google OAuth client secret and the
service-account key (`google-service-account.json`) are supplied locally and are git-ignored.
