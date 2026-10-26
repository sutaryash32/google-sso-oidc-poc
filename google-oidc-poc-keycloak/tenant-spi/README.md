# tenant-spi

> **Current design: hub-and-spoke.** The plugin's current job is `HubTenantGateMapper` (last row of the table). `TenantResolverMapper`, `TenantGuardMapper`, `NoEmailLinkAuthenticator` and the registry belong to the earlier single-realm design, which still runs as a fallback.

A small Keycloak plugin (an identity-provider mapper) that decides **which tenant a login belongs to** and
refuses everything else. It runs on every brokered login, *before* Keycloak creates or links any user.

For each login it checks, in order: the ID token has an `hd` claim → the email is present and verified → `hd`
resolves to exactly one tenant in `tenant-registry.json` → that tenant is active and SSO-enabled → the email's
domain belongs to the same tenant → the discovery hint (`login_hint`), if any, resolves to the same tenant → an
already-provisioned user is not bound to a different tenant or to a different provider subject. Any failure returns
403, creates no user and issues no token; the reason is logged as `TENANT_DENIED reason=...`. On success it stamps the
user with the admin-only attributes `tenant_id`, `tenant_domain`, `idp_alias` and `idp_subject` (the provider's own
subject for the person: the stable key, unlike Keycloak's user id), which protocol mappers copy into the tokens.

| Class | Role |
|---|---|
| `TenantResolver` | The decision logic. No Keycloak types, so it is unit-tested directly. |
| `TenantRegistry`, `FileTenantRegistry` | Domain → tenant lookup. The file implementation reloads when the file changes and fails closed. |
| `TenantResolverMapper` | The Keycloak integration (`preprocessFederatedIdentity`, `importNewUser`, `updateBrokeredUser`). Stamps `tenant_id`, `tenant_domain`, `idp_alias`, `idp_subject`. |
| `NoEmailLinkAuthenticator` | Replaces "Handle Existing Account" in a copy of the first-login flow: a new provider identity is never linked to an existing user by email. |
| `TenantGuardMapper` | A token-time check: refuses to issue any token, including a refresh, for an unknown, suspended or SSO-disabled tenant. |
| `HubTenantGate`, `HubTenantGateMapper` | **The current design's gate.** Pure logic in `HubTenantGate` (unit-tested), claims read by the mapper. On a tenant realm's `google-hub` IdP it reads the claims master passes on (`google_hd`, `google_email_verified`, `google_sub`); on master's own Google IdP (`claim.prefix=raw`, `gate.name=master`) it reads Google's raw claims (`hd`, `email_verified`, `sub`). Before any user is created it requires the `hd`, a verified email and the email's domain to belong to `allowed.domains` (that tenant's domains; on master, all tenants'), a Google subject, and no conflicting subject for a known user. Every missing claim is a denial; an empty domain list denies everyone. Set up and kept current by `../scripts/setup-tenant.mjs`. |

## Build

You normally do not build it by hand: `../Dockerfile` compiles it (and runs its 46 unit tests) while building the
Keycloak image, and the backend triggers that build the first time it starts the stack.

```powershell
mvn package        # only for working on the plugin locally: runs the 46 unit tests, produces target/tenant-spi.jar
```

## How it is wired

- `../Dockerfile` builds this project and copies the jar into Keycloak's `providers/` folder; `../docker-compose.yml`
  builds the `oidc-poc-keycloak-tenant` image from it (the test harness uses the same image) and mounts
  `../tenant-registry.json` as the registry.
- `../scripts/enable-multitenancy.mjs` attaches the mapper to the Google IdP.
- After changing this project, rebuild and restart: `docker compose build keycloak` then `docker compose up -d`
  (run in `google-oidc-poc-keycloak/`). Without the rebuild Keycloak keeps running the old plugin.

## Caveats

- Keycloak labels the mapper SPI **internal** and may change it between versions. Pin the Keycloak version and
  re-run the harness (`../test-harness`) after any upgrade.
- Verified against a mock Google, not yet with a real Google sign-in. See the harness README for what was and was not proven.
