# Google Workspace SSO on the SecuFusion hub-and-spoke model

Design only. Nothing here is built. It supersedes the shared-realm tenant resolution used by this POC
(see "Implementation impact" for what is reused and what is not).

**Basis.** Read from the SecuFusion code in `Desktop\secufi_full` (`sfn-tenants-api`, `sfn-iam-api`, `sfn-events-api`,
`sfn-web-ui`, `snf-browser-extn`). File and line references are to that tree. Google behaviour claims come from this POC's
own earlier work (the `hd` claim, `org_internal`) and are marked **[to verify]** where they have not been tested against real
Google in a hub-and-spoke chain. Production values (the real `masterAzureAlias`, the production Keycloak version) were not
visible: only configuration placeholders and a local compose file (Keycloak 26.0.0).

---

## 1. CURRENT AZURE FLOW

```
Browser / extension
   -> Tenant realm (own issuer)         IdP "master-hub"  (keycloak-oidc, trustEmail=true)
   -> Master realm                       client "broker-for-<tenantRealm>"  (one per tenant)
   -> Master realm IdP (alias from masterAzureAlias, providerId "oidc")   <- ONE shared IdP
   -> Entra (login.microsoftonline.com/common, multi-tenant app registration)
```

Return path: Entra token -> master IdP mappers (`tid`, `roles`, `groups` into user attributes `azure_tenant_id`,
`azure_roles`, `azure_groups`) -> broker client protocol mappers put them in the master token -> tenant realm `master-hub`
IdP mappers import them -> tenant client protocol mappers put them in the **tenant-issued JWT** -> backend.

What `TenantService.setupHubAndSpokeSSO` (`TenantService.java:1348`) provisions, in order:

| Step | Object | Where |
|---|---|---|
| 1 | Shared Azure IdP, created once | master |
| 2 | Organization for the tenant, shared IdP linked to it (non-fatal) | master |
| 3 | Broker client `broker-for-<tenantRealm>`, redirect URI `<kc>/realms/<tenantRealm>/broker/master-hub/endpoint` | master |
| 4 | IdP `master-hub` (`keycloak-oidc`, `trustEmail`, `loginHint`, `acceptsPromptNoneForwardFromClient`) and its mappers | tenant realm |
| 4.5 | Auto-link first-broker-login flow (links an existing user **by email**, no review/confirm) | tenant realm |
| 4.6 | Suppress broker profile prompts | tenant realm |
| 5 | Auto-redirect to `master-hub` | tenant realm |
| 6 | Client protocol mappers for `azure_tenant_id`, `azure_roles`, `azure_groups` | tenant realm |
| 7 | Align master session lifetimes with tenant refresh tokens | master |

How the Azure tenant is established and enforced (all in the application, none in Keycloak):

- `tenant.azure_tenant_id` is **bound on the default user's first login** (`AuthConfigService.java:361-370`) and compared with
  the token's `azure_tenant_id` afterwards. That check only runs when `azure.mismatch.validation` is true, and its default is
  **FALSE** (`AuthConfigService.java:48`).
- `ExtensionPrincipalGate` (extension enrollment) compares the token's `azure_tenant_id` with `tenant.azure_tenant_id` and
  applies an email-domain allowlist (`tenant email domain` plus `enrollment_allowed_domains`). It defaults to **AUDIT** (log
  only), and the issuing-org check fails open when the tenant is unbound or the claim is absent.
- Token validation is per issuer: the realm is taken from the `iss` claim (`JwtUtl.java:184-187`).

Groups: Entra puts `groups` in the token; past 200 entries Entra omits the claim, so `AuthConfigService` falls back to one
Graph call, and `AzureGroupSyncService` caches groups in `events_groups`.

---

## 2. PROPOSED GOOGLE HUB-AND-SPOKE FLOW

```
Browser / extension
   -> Tenant realm (own issuer)          IdP "google-hub"  (keycloak-oidc)
   -> Master realm                        client "broker-google-for-<tenantRealm>"   (one per tenant)
   -> Master realm IdP "google"           (Keycloak's Google provider)               <- ONE shared IdP
   -> Google Workspace (accounts.google.com)
```

```mermaid
sequenceDiagram
    actor U as Workspace user
    participant S as App (tenant realm client)
    participant T as Tenant realm
    participant M as Master realm
    participant G as Google
    U->>S: Sign in
    S->>T: auth request, kc_idp_hint=google-hub
    T->>M: broker request via google-hub (client broker-google-for-realm)
    M->>G: kc_idp_hint=google, hd=*, prompt=select_account
    G-->>M: ID token (sub, email, email_verified, hd)
    M->>M: google IdP mappers: sub, hd, email_verified -> user attributes
    M-->>T: master token with google_sub, google_hd, google_email_verified
    T->>T: TENANT GATE: hd bound to this realm? email_verified? email domain ok?
    T-->>S: tenant-realm JWT (iss = tenant realm) with google_sub, google_hd, idp_type
    S->>S: call backend with the JWT; backend validates per issuer and re-checks the binding
```

Answers to the specific questions:

**How does a tenant realm reach the shared Google IdP?** Exactly as Azure does: the tenant realm's `google-hub` IdP points at
the master realm's OIDC endpoints with `kc_idp_hint=google` in the authorization URL, so master skips its login screen. Master
has the identity-provider redirector disabled (`KeycloakAdminUtil.disableMasterIdpRedirector`), so with two IdPs in master
(Azure and Google) the hint is the **only** selector.

**Is a separate `google-hub` IdP required?** Yes. The alias fixes the broker callback path
(`.../broker/<alias>/endpoint`), the redirect URI registered on the master client, the mapper set, and the hint. Reusing
`master-hub` would make a tenant either-or, couple Google's mapper set to Azure's cleanup code (section 7), and make "disable
Google for this tenant" indistinguishable from "disable Azure". A new alias costs nothing.

**Is a `broker-for-<tenant>` equivalent required?** Yes, one **per tenant realm**, and I recommend a separate client
(`broker-google-for-<tenantRealm>`) rather than adding a second redirect URI to the existing one. Reasons: separate secret and
revocation, a separate mapper set (the current mapper cleanup deletes anything outside `azure_tenant_id, roles, groups`), and
no dependency on the Azure provisioning code path. The client exists so that master can tell which tenant realm is asking and
only redirect back to that realm's callback.

**Should Organizations be used?** Use them the same way for parity (one Organization per tenant in master, the shared Google IdP
linked to it, the tenant's verified domain attached) because it gives an inventory of "which tenant owns which domain" in
master. **Do not treat an Organization as the tenant boundary.** Azure does not either: it routes with `kc_idp_hint`, not with
organization login. An Organization carries a domain string, not a Google-verified fact. Organizations need Keycloak 26+; this
POC runs 24.0.3, so a faithful POC needs the upgrade (SecuFusion's local stack is already 26.0.0).

**Why this answers the earlier scaling problem.** With a realm per tenant and Google brokered directly, every realm needs its
own redirect URI registered in the Google Cloud OAuth client. In hub-and-spoke, Google only ever sees master's single callback
(`/realms/master/broker/google/endpoint`). **Adding a tenant requires no Google Cloud change.**

---

## 3. REQUIRED KEYCLOAK OBJECTS

**Master realm (once)**

| Object | Detail |
|---|---|
| IdP `google` | Built-in Google provider; one Google OAuth client; Hosted Domain `*` (requires an `hd` claim, so consumer Gmail is rejected); `prompt=select_account`; scopes `openid email profile`; `loginHint` and `acceptsPromptNoneForwardFromClient` on |
| IdP mappers on `google` | `sub` -> `google_sub`; `hd` -> `google_hd`; `email_verified` -> `google_email_verified` (attribute importers) |
| Redirector | Identity-provider redirector stays disabled |

**Master realm (per tenant)**

| Object | Detail |
|---|---|
| Client `broker-google-for-<tenantRealm>` | Confidential; redirect URI `<kc>/realms/<tenantRealm>/broker/google-hub/endpoint` only |
| Client protocol mappers | `google_sub`, `google_hd`, `google_email_verified` from user attributes into the access/ID token |
| Organization (optional) | Tenant name and verified domain; `google` IdP linked |

**Tenant realm (per tenant)**

| Object | Detail |
|---|---|
| IdP `google-hub` | `keycloak-oidc`; authorization URL `<kc>/realms/master/protocol/openid-connect/auth?kc_idp_hint=google`; client id/secret of the broker client; `loginHint`, `acceptsPromptNoneForwardFromClient`; **`trustEmail=false`** (see section 5) |
| IdP mappers on `google-hub` | Import `google_sub`, `google_hd`, `google_email_verified` into user attributes |
| **Tenant gate** | An identity-provider mapper (the existing SPI, simplified) on `google-hub`: runs before the user is created (section 5) |
| First-broker-login flow | A flow that links only a control-plane-pre-provisioned user, once (section 5), not the Azure auto-link-by-email flow |
| Client protocol mappers | `google_sub`, `google_hd` as claims; constant claim `idp_type=google`; audience if used |
| User profile | Admin-only attributes `google_sub`, `google_hd` (the user must not be able to edit them) |

**Control plane (`sfn-tenants-api`)**

New tenant columns: `sso_type = GOOGLE`, `google_hosted_domains`, `google_customer_id` (nullable, bound later),
`google_delegated_admin`, `google_domain_verified_at`. The gate reads the bound domains from the realm's `google-hub` IdP
config, written by the control plane at provisioning, so the Keycloak hop does not call back into the database at login.

---

## 4. CLAIM MAPPING DESIGN

| Source claim | Master IdP | Broker client claim | Tenant `google-hub` IdP | App JWT claim | Used for |
|---|---|---|---|---|---|
| `sub` | `google_sub` | `google_sub` | `google_sub` (admin-only attr) | `google_sub` | **Stable person key** (below) |
| `hd` | `google_hd` | `google_hd` | `google_hd` | `google_hd` | Tenant binding: the analogue of Azure `tid` |
| `email` | standard | standard | standard | `email` | Display, allowlist check. **Never** the identity key |
| `email_verified` | `google_email_verified` | same | same | not emitted | Gate input only |
| `name`, `given_name`, `family_name` | standard | standard | standard | standard | Profile |
| (none) | | | | `idp_type=google` | Lets the backend branch Azure/Google |
| (none) | | | | `iss` = tenant realm | Unchanged per-issuer validation |

**Person key.** In a hub chain, the tenant realm's federated-identity link stores the **master user's Keycloak id**, which changes
if that master user is deleted and recreated. The stable key is Google's `sub`. It must travel as an explicit attribute
(`google_sub`) through both hops, and be bound on the tenant-realm user at first login. The backend keys on
`(issuer, google_sub)`.

**Can the Azure plumbing be generalized?** Partly. The structure (attribute mapper at each hop, client protocol mapper at each
hop) is provider-neutral; the **names and the cleanup allowlists are not** (section 7). Recommendation: add Google as
**additive parallel claims** (`google_*`, plus the neutral `idp_type`) for Phases 1-2, with zero changes to Azure behaviour.
Generalize to neutral names (`idp_tenant_id` = Azure `tid` or Google `hd`) later, dual-emitting both for one release so the
Azure consumers (`ExtensionPrincipalGate`, `AuthConfigService`, `EnrollmentPrincipalGuard`) migrate safely.

**Groups.** Google ID tokens carry no groups claim and no roles. Nothing for Google equals Entra's `groups`/`roles` mappers.

---

## 5. TENANT VALIDATION DESIGN

**The exposure.** The master Google IdP authenticates a user from *any* Workspace. Any such user can be sent through
`broker-google-for-realmA`. Without a check, realm A's `google-hub` would create or link a user in realm A. For Azure, this is
covered by `tid` binding, but only in the application and, by default, switched off or audit-only (section 1). Google must not
copy those defaults.

| Option | Verdict |
|---|---|
| **`hd` claim** | Signed by Google, present only for managed organizations. A domain string, not an immutable id; behaviour for alias and secondary domains is **[to verify]** (the open spike). Necessary, not sufficient |
| **Domain allowlist** (`enrollment_allowed_domains`) | An email-domain filter on the principal. Right as an additional gate, wrong as identity: it depends on the `email` claim and on how aliases are issued. Keep its current role |
| **Tenant registry** (this POC's JSON file) | In hub-and-spoke the registry is the tenant table plus the realm's IdP config. The file goes away; the *logic* stays |
| **First-login trust** (Azure: bind on first login, link by email) | Weakest. Whoever signs in first from a given directory defines the tenant; email-linking turns any matching email into account takeover |

**Recommended (strongest to weakest, all layered):**

1. **Bind at provisioning, not at first login.** The control plane records the tenant's Google domain(s) after a domain-ownership
   proof (DNS TXT), and writes them to the realm's `google-hub` config.
2. **Gate in the tenant realm, before the user exists, fail closed:** `google_hd` must be in the realm's bound domains,
   `google_email_verified` must be true, and the email's domain must be in the tenant's domains (`hd` plus declared secondary
   domains). Any other result: access denied, no user created, no token. (This is this POC's SPI, minus the shared registry.)
3. **Bind the Workspace customer id** once domain-wide delegation is authorized: the Directory API returns a stable
   `customerId`. It survives domain renames and takes the place Azure's immutable `tid` has. Compare it afterwards.
4. **Backend re-check, enforcing, from day one:** the API verifies `google_hd` (and `customerId` when bound) against the tenant
   row on every request, not behind a default-off flag and not in an audit-only mode.
5. **First link:** `trustEmail=false`. Link an existing realm user **only** if the control plane pre-provisioned them (a marker
   attribute, single use), then bind `google_sub` and never match by email again. This keeps Azure's "pre-created admin, no
   password prompt" convenience without Azure's "any matching email links silently".
6. **Master hygiene (Phase 2, optional):** also reject at master any `hd` that no tenant owns, so master does not accumulate
   users from organizations that are not customers.

Suspension: disable `google-hub` in the tenant realm, unlink or disable in master, and revoke the realm's sessions. The
backend check makes it effective on the next request.

---

## 6. IMPLEMENTATION IMPACT

**Groups: recommended approach.** Not through token claims (Google has none). Use the **Directory API with domain-wide
delegation**, as this POC already does:

- One platform service account; each tenant's super admin authorizes its Client ID with read-only Directory scopes
  (`google_delegated_admin` in the tenant row).
- Cache into the existing `events_groups` table with a source column (as `AzureGroupSyncService` does for Entra), refreshed on
  first login and on a schedule. Do not call Google on every request.
- Never put group names in tokens; if they ever are, namespace by tenant.

**Phased plan**

| Phase | Scope | Exit criterion |
|---|---|---|
| 1. Authentication only | Master `google` IdP; per-tenant broker client and `google-hub`; mappers for `google_sub`, `google_hd`, `google_email_verified`; client mappers and `idp_type`; `ssoType=GOOGLE` in the login UI | One tenant signs in; the JWT's `iss` is the tenant realm and carries `google_sub` and `google_hd` |
| 2. Tenant validation | Tenant columns; domain-ownership proof; tenant gate; enforcing backend check; first-link rule; suspension; `customerId` binding | An `hd` from another organization and a personal Gmail are rejected with no user created; every denial is logged |
| 3. Group synchronization | Directory API, DWD onboarding, `events_groups` cache, sync status | A tenant's groups appear in the cache and survive a token with no group claim |
| 4. Advanced authorization | Map groups to existing roles through `mappedGroups`; neutral claim names (`idp_tenant_id`); optional per-tenant realm customization | Authorization decisions use synchronized groups |

**Hardcoded Azure assumptions that block Google** (verified in code):

| Where | Assumption |
|---|---|
| `TenantService.java:1495`, `KeycloakAdminUtil.java:2567` | Literal `kc_idp_hint=microsoft`. Line 2598 uses `masterAzureAlias` instead, so the two already disagree |
| `TenantService.java:1483-1509` | Alias `"master-hub"` fixed |
| `TenantService.java:1348-1465`, `:1385`, `:1469` | One flow, one broker client name `broker-for-<realm>`, one shared IdP property set (`masterAzureAlias/ClientId/ClientSecret`) |
| `KeycloakAdminUtil.java:1961-2023` | Shared IdP is always `oidc` with `login.microsoftonline.com/common` endpoints and an empty issuer |
| `KeycloakAdminUtil.java:2103, 2159, 2241, 2364, 2415, 2473` | **Mapper cleanup allowlist** `{azure_tenant_id, roles, groups}`: any other mapper on the same object is **deleted** on provisioning or repair. Google mappers on a shared object would be wiped |
| `KeycloakAdminUtil.java:2181, 2436, 2494` | Client mapper creation hardcodes the Azure claim names |
| `TenantService.java:1423-1424` | `ensureAutoLinkFirstBrokerFlow` links by email with trusted email |
| `TenantService.java:4633-4643` | Teardown disables `"master-hub"` and unlinks `masterAzureAlias` |
| `JwtUtl.getAzureTenantIdFromToken`, `AuthConfigService.java:342-405`, `ExtensionPrincipalGate`, `EnrollmentPrincipalGuard`, `Tenant.azureTenantId` | Tenant binding reads only `azure_tenant_id`; unbound or absent claims fail open |
| `AzureGroupSyncService`, `AzureGraphService`, the `groups` overage fallback | Group source is Entra only |
| `sfn-web-ui/.../TenantLogin.jsx` (`isAzureSso`, Microsoft button, email-first `login_hint`) | Login UI branches on `ssoType === 'AZURE'` |
| `snf-browser-extn/background.js:8642` | `cfg.idpHint \|\| 'master-hub'`: already configurable, so it is the one place that needs only configuration |

**What happens to this POC.** Reusable: the tenant-gate logic and its tests (the `hd`, `email_verified` and domain checks), the
claim-propagation tests, the mock-Google harness, the backend's token validators. Not reusable: the shared-registry file and
`hd -> tenant` resolution, the single-realm client mappers, the `tenant.mjs` registry CLI. The POC's documents
(`pitch.md`, the READMEs, `multi_tenant_saas_design.md`) describe the shared-realm design and would need rewriting if this
design is adopted.

---

## 7. RISKS

1. **Fail-open defaults copied from Azure.** `azure.mismatch.validation=FALSE`, gate `AUDIT`, unbound-tenant pass-through.
   For Google the tenant check must be enforcing from the first release.
2. **Email-linking account takeover** (the Azure auto-link flow). Mitigation in section 5, rule 5.
3. **Mapper cleanup deletes Google mappers** if any Azure routine runs against a shared client or IdP, including repair jobs.
   Mitigation: separate objects and a provider-keyed mapper set.
4. **Master blast radius.** One shared Google client secret and one master user store. Already accepted for Azure.
5. **`hd` is a domain, not an id.** Domain transfer and takeover. Mitigation: domain-ownership proof, `customerId` binding,
   periodic re-verification.
6. **Alias and secondary domains [to verify].** A user whose email is on a secondary domain may carry `hd` = the primary
   domain. The allowlist must include declared secondary domains, and the open spike must confirm the behaviour.
7. **Google has no RP-initiated logout** [to verify]. Federated logout ends the master and tenant sessions but not the user's
   Google session, so the Azure federated-logout runbook does not carry over. Keep `prompt=select_account`; the next sign-in
   shows the account picker rather than silently reusing the Google account.
8. **Consent screen must be External** for other organizations; an Internal screen blocks everyone outside the owning
   organization (this is what the earlier `org_internal` test showed). Basic scopes (`openid email profile`) do not need
   Google verification [to verify for production].
9. **Keycloak version.** Organizations need 26+. This POC is on 24.0.3. The existing SPI is built against the 24 API.
10. **Keycloak `hd` handling.** A past `hd` bypass existed on a token-exchange path (CVE-2026-18214 in earlier notes). The
    tenant realm's own `hd` check is therefore not optional: it is the control that does not depend on Keycloak's Hosted
    Domain setting.
11. **Silent mapper breaks.** A missing mapper at any of the four hops drops a claim without an error. Add a provisioning
    self-test (the Azure code already has a "diagnostic").
12. **Untested with real Google in this chain.** Everything about `hd` in a hub-and-spoke chain is design until a real
    Workspace and an alias/secondary-domain account have been run through it.

---

## 8. FINAL RECOMMENDATION

Adopt hub-and-spoke for Google. Keep the Azure model's shape: one shared Google IdP in master, one `google-hub` IdP and one
broker client per tenant realm, per-issuer token validation, and `kc_idp_hint` selection. Use a **separate alias and a separate
broker client** from Azure. Use Organizations for inventory, **not** as a trust boundary.

Change what Azure does where it is weak:

- Establish the tenant at **provisioning** (verified domain, later the Workspace `customerId`), not at first login.
- Enforce it in the **tenant realm before any user exists** and again in the **backend**, both **fail-closed**.
- Key people on Google's **`sub`**, carried explicitly through both hops; never on email or the master user id.
- Set `trustEmail=false` and link only control-plane-pre-provisioned users, once.
- Use the **Directory API with domain-wide delegation** for groups (Phase 3); do not expect groups in the token.

Build in the four phases of section 6. Before Phase 1, three things need an answer: confirm the production Keycloak version
supports Organizations, run the alias and secondary-domain spike with real Google, and agree that the Google tenant check
ships enforcing rather than in audit mode.
