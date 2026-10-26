# Multi-Tenant Google Workspace SSO Platform — Architecture Review & Recommended Design

> **Review update:** [architecture_validation.md](architecture_validation.md) challenges this design and found changes
> that supersede parts of it: §7 (the user key must be the provider subject, not the Keycloak `sub`), §4 (replace the default
> first-broker-login flow so accounts are never linked by email), and the suspension behaviour (sessions must be revoked).

Scope: a SaaS platform where many independent customer organizations
(`acme.com`, `globex.com`, `contoso.com`, …) sign in with their own Google
Workspace, Keycloak is the authentication broker, and Spring Boot services act
as OAuth2 Resource Servers. Optional Google group sync via Domain-Wide
Delegation (DWD). Strong tenant isolation is a hard requirement.

This is a design document, not an implementation. Items I could not confirm
against current vendor documentation are collected in **§12 "Verify before
committing"**; they are also marked *(verify)* inline.

---

## 0. Summary of recommendations

| Question | Recommendation |
|---|---|
| Tenant key | A platform-owned opaque `tenant_id`. Domains are *attributes* of a tenant (many-to-one), never the key. |
| How the tenant is determined | From the Google ID token's **`hd` claim**, validated by Keycloak at login against a **tenant domain registry**. Email domain is a UX/routing hint only. |
| Keycloak topology | **One realm, one shared Google IdP**, tenant resolved and enforced by a pre-provisioning identity-provider mapper (SPI) plus token mappers. Realm-per-tenant only as an exception tier. |
| Hosted Domain | Set to `*` (any Workspace org, no consumer Gmail) as a coarse gate. **Not** a security boundary. Enforcement = registry allow-list. |
| Token | Small, stable claims: identity + `tenant_id` + `tenant_domain`. No volatile authorization data (group lists) in the JWT. |
| Backend isolation | Tenant comes **only** from the validated JWT; every table carries `tenant_id`; Postgres Row-Level Security as a second layer; automated cross-tenant tests. |
| User key | Internal `user_id`, unique on `(tenant_id, idp_subject)`. Email is a mutable attribute. |
| Group sync | Per-tenant DWD authorization, delegated admin stored per tenant, secrets in KMS, groups→roles via tenant-managed mappings, fail closed. |
| Scale | Single realm scales to 1000+ tenants; realm-per-tenant stops being practical well before that. |

---

## 1. Tenant identification strategy

### 1.1 Options

| Signal | Trustworthy? | Notes |
|---|---|---|
| **Email domain** (`user@acme.com`) | Partly | Comes from the `email` claim. Fine as a routing hint before login. Weak as an authority: domain aliases/secondary domains, and the claim is only as good as its verification. |
| **`hd` claim** (Google "hosted domain") | **Yes, strongest available at login** | Signed by Google inside the ID token; present only for Workspace/Cloud Identity accounts, absent for consumer Gmail. Binds the user to a Workspace org, not just a string. |
| **Custom tenant identifier** (`tenant_id`) | Yes — it's yours | Must be derived server-side from a trusted signal (the `hd`), never supplied by the client. |
| **Request parameter / subdomain** (`acme.app.com`) | No (as an authority) | Great UX for discovery, but a user can type any subdomain. Must be *checked against* the token's tenant, never trusted. |

### 1.2 Recommended model

1. **`tenant_id`** (UUID or similar opaque id) is the primary key and appears in
   the JWT and every database row.
2. A **`tenant_domain` registry** maps verified domains → `tenant_id`
   (`acme.com`, and later `acme.co.uk`, etc.). A tenant can own several domains.
3. At login, the authoritative input is the **`hd` claim**. Lookup:
   `hd → tenant_domain → tenant_id`. Unknown or inactive → deny.
4. **Email domain** and **subdomain** are used only to *choose where to send the
   user* (discovery). After login, the server compares: discovered tenant must
   equal the tenant derived from `hd`, otherwise reject.
5. Domains need **ownership proof** at onboarding (DNS TXT record), because `hd`
   proves "this person is in Workspace X", not "this person may register X as a
   tenant". See §10.5.

> Edge cases to design for: alias/secondary domains (does `hd` report the
> primary domain?) *(verify)*; domain expiry and re-registration by a different
> party (re-verify DNS periodically); users with accounts in several orgs (one
> Google `sub` per org account — handled by the identity model in §7).

---

## 2. Keycloak architecture — comparison

Four patterns, evaluated for a platform that must grow to many tenants.

| | Single realm, shared IdP | Single realm, IdP per tenant | Realm per tenant | (Reference) Shared IdP across realms |
|---|---|---|---|---|
| Google redirect URIs | **1** | 1 per tenant alias | 1 per realm | 1 per realm |
| Google OAuth client | 1 | 1 (many URIs) | 1 (many URIs) | 1 |
| Tenant restriction | Registry check in login flow | Native `hd` per IdP | Native per realm | Native per realm |
| Isolation | Logical (your code + data) | Logical | **Strongest** (separate users/roles/issuer) | Strong |
| Per-tenant policy (session length, MFA, branding) | Limited | Limited | **Full** | Full |
| Operational load at 1000 tenants | Low | Medium–High (1000 IdP configs) | **Very high** | Very high |
| Backend validation | Single issuer | Single issuer | **Multiple issuers** | Multiple issuers |
| Custom code in Keycloak | Yes (small SPI) | Optional | Optional | Optional |

### 2.1 Key discriminators

- **Google redirect URI registry.** Every Keycloak IdP alias (and every realm)
  has its own broker redirect URI:
  `…/realms/{realm}/broker/{alias}/endpoint`. Per-tenant aliases or realms mean
  registering one more URI in the Google OAuth client per tenant, and Google
  limits how many URIs a client can hold *(verify current limit)*. A shared IdP
  needs exactly one URI forever. This alone favors the shared IdP.
- **Onboarding is a Google Cloud change, not just a Keycloak change** under the
  per-tenant patterns. That breaks self-service onboarding.
- **Keycloak realm count.** Keycloak is commonly run with dozens of realms;
  thousands are widely reported as problematic (startup/cache load, admin
  console, upgrade migrations iterate every realm) *(verify against current
  Keycloak scaling guidance)*.
- **Newer Keycloak versions include an Organizations feature**
  (tenant-like grouping of users/domains/IdPs inside one realm). Keycloak
  24.0.3 as used in the POC does not have it; evaluate it before building a
  custom tenant layer *(verify availability and maturity in the version you
  target)*.

### 2.2 Recommendation

**One realm + one shared Google IdP (`google`) with registry-driven tenant
resolution.**

Why: constant Google configuration regardless of tenant count; self-service
onboarding with no Google Cloud or Keycloak per-tenant change; single issuer for
all backends; cheap to operate at 1000 tenants. The cost is that isolation is
logical rather than physical — which is acceptable *because* the backend
enforces isolation on its own (§6) and does not rely on Keycloak to separate
tenants' data.

**Exception tier:** a tenant that needs its own policies, its own IdP (SAML or a
different OIDC provider), or contractual hard isolation gets a dedicated realm
(or a dedicated Keycloak). Design the backend for multi-issuer from day one so
this is possible later (§6.4), even if you start with one issuer.

---

## 3. Google OIDC architecture

### 3.1 One OAuth client for the platform

- Single Google OAuth client (Web application) owned by the platform.
- **Consent screen: External**, published to production (Internal only admits
  your own org). Scopes `openid email profile` are non-sensitive; confirm
  current verification and branding requirements for your case *(verify)*.
- Redirect URI: the single Keycloak broker endpoint
  `https://sso.<platform>/realms/<realm>/broker/google/endpoint`.
- Separate OAuth clients per environment (dev/stage/prod).

### 3.2 Hosted Domain

| Option | Verdict |
|---|---|
| Fixed single domain (`yserious.com`) | **Remove** — wrong for multi-tenant. |
| One IdP per tenant with its own `hd` | Rejected in §2 (redirect URI growth, IdP sprawl). |
| **`*`** | **Use.** Keycloak's Google provider treats `*` as "any hosted domain": Workspace accounts only, consumer Gmail excluded *(verify exact behavior on your version)*. |
| Dynamic per-request `hd` | Not a standard Keycloak feature (the value is IdP config). Use **`login_hint`** instead (Keycloak can forward it; Google pre-fills and routes the account). |

Also set **`prompt=select_account`**: multi-tenant users often hold several
Google accounts, and silent reuse of the wrong one is a common support issue.

### 3.3 What actually enforces tenant restrictions

`hd=*` is a coarse filter and a UX hint — **not a security boundary**. The real
controls, in order:

1. **Registry allow-list at login.** The ID token's `hd` must resolve to an
   **active** tenant domain (§4, step 6). Enforced inside Keycloak so that no
   token is ever issued for an unknown org.
2. **Backend re-validation.** Resource servers verify `tenant_id` exists and is
   active; never assume Keycloak did it.
3. **Data-layer isolation** (§6), which assumes tokens may be wrong.

Also require `email_verified = true` and a present `hd`.

---

## 4. Login flow (User → Google → Keycloak → Backend)

```
 1 Discover      2 Redirect       3 Authenticate     4 Post-login checks
┌───────────┐   ┌───────────┐    ┌──────────────┐   ┌──────────────────────────┐
│ SPA asks  │   │ SPA ->    │    │ Google       │   │ Keycloak post-broker flow │
│ for work  │──▶│ Keycloak  │───▶│ OIDC login   │──▶│ verifies hd -> tenant     │
│ email /   │   │ kc_idp_   │    │ (hd=*,       │   │ creates/links user, sets  │
│ subdomain │   │ hint=     │    │ login_hint)  │   │ tenant attributes         │
└─────┬─────┘   │ google    │    └──────────────┘   └────────────┬─────────────┘
      │         └───────────┘                                    │
      ▼                                                          ▼
 Tenant Directory API                                  5 Token issuance
 domain -> tenant (active?,                            Keycloak mappers add tenant_id,
 SSO enabled?)                                         tenant_domain, aud; short life
                                                                 │
                                                                 ▼
                                                      6 API call w/ Bearer JWT
                                                      7 Backend: validate -> tenant
                                                         context -> authorize -> scoped
                                                         data access
```

### Step by step

1. **Tenant discovery (UX only).** User enters a work email, or arrives on a
   tenant subdomain. The app calls a public *Tenant Directory* endpoint:
   `domain → { tenant exists, SSO enabled }`. Return no tenant details to
   unauthenticated callers (avoid tenant enumeration: respond uniformly).
2. **Redirect.** SPA starts the Authorization Code + PKCE flow against
   Keycloak with `kc_idp_hint=google` and `login_hint=<email>`.
3. **Authenticate.** Google signs the user in (Workspace credentials, the org's
   2SV and conditional access apply). Keycloak receives the code and validates
   the ID token (signature, nonce, `email_verified`).
4. **Tenant enforcement at the broker boundary** (a small Keycloak
   identity-provider mapper SPI whose `preprocessFederatedIdentity` hook runs
   *before* any user is created or linked — or the platform Organizations
   feature if adopted). *Spike result:* an enforcement point that runs after
   user provisioning, such as a post-login authenticator, would leave an
   orphan account for every denied login; the pre-provisioning hook leaves
   none. See `google-oidc-poc-keycloak/test-harness/README.md`.
   - read `hd`, `sub`, `email`, `email_verified` from the broker context;
   - reject if `hd` missing or `email_verified` false;
   - look up `hd` in the tenant registry; reject if unknown, suspended, or SSO
     disabled — with a user-friendly "your organization is not enabled" page;
   - if the discovery hint (step 1) named a different tenant, reject;
   - find the user by federated identity `(google, sub)` — **never link by
     email**; create on first login;
   - write **admin-only** user attributes `tenant_id`, `tenant_domain`.
5. **Token issuance.** Protocol mappers copy those attributes into the access
   token; an audience mapper sets `aud`. Access tokens are short-lived
   (≈5 min); refresh tokens governed by SSO session limits.
6. **API call.** SPA sends `Authorization: Bearer <access token>`.
7. **Backend.** Validate signature/issuer/audience/expiry → extract tenant →
   load roles for `(tenant_id, user)` → authorize → execute tenant-scoped
   queries. Authorization details in §6.

> User attributes that carry tenancy must be **read-only to the user**.
> Configure Keycloak's user profile so users cannot edit `tenant_id` or
> `tenant_domain` through the account console or any API.

---

## 5. JWT design

### 5.1 Claims

| Claim | Source | Purpose |
|---|---|---|
| `iss`, `aud`, `exp`, `iat`, `azp` | Keycloak | Standard validation. `aud` = the API's identifier. |
| `sub` | Keycloak user id | Stable subject. |
| `tenant_id` | Keycloak user attribute (set by login flow) | **Isolation key. Authoritative.** |
| `tenant_domain` | same | Display/diagnostics (the verified `hd`). Never an authorization input. |
| `email`, `email_verified`, `name` | Google via Keycloak | Display and audit. Email is not an identity key. |
| `idp` (e.g. `google`) | session note / mapper | Diagnostics; also future per-tenant IdP types. |
| `roles` | optional, coarse | e.g. platform-level flags only. Tenant roles are resolved in the app (below). |

### 5.2 What not to put in the token

- **Group lists.** They can be large (token bloat → header-size failures) and
  change faster than a token lives (stale authorization).
- **Fine-grained tenant roles.** Same staleness problem; revocation would lag
  the token lifetime.
- **Anything the client could influence.**

Recommended split: **the token proves who and which tenant; the app database
decides what they may do.** Keep access tokens ≈5 minutes so tenant
suspension/offboarding takes effect quickly, and check tenant status on each
request (cached briefly).

---

## 6. Backend security model

### 6.1 Tenant context

- A single security filter, after JWT validation, builds an immutable
  `TenantContext(tenantId, userId)` from the token. No other code path may set
  it.
- **No endpoint accepts a tenant identifier as authority.** If a path includes
  `/tenants/{id}/…`, it must equal the token's `tenant_id` or the request fails
  (404 rather than 403 to avoid confirming existence).
- The tenant status (active/suspended) is checked per request from a short-TTL
  cache; a suspended tenant gets 403 everywhere.
- Background jobs and async handlers receive `tenantId` explicitly and
  re-establish context; nothing relies on thread-local leakage.

### 6.2 Data layer — defense in depth

1. **Schema:** every tenant-owned table has `tenant_id NOT NULL`; all uniqueness
   constraints and foreign keys are **composite with `tenant_id`**
   (e.g. `UNIQUE (tenant_id, name)`, `FOREIGN KEY (tenant_id, order_id)`), so a
   cross-tenant reference is *impossible to store*.
2. **ORM layer:** discriminator-based tenancy (e.g. Hibernate's tenant-id
   support) or a mandatory query filter so queries cannot omit the predicate.
3. **Database layer:** PostgreSQL **Row-Level Security** with a per-transaction
   setting (`SET LOCAL app.tenant_id = …`). Requirements: the application
   connects as a role that is **not** the table owner and not superuser (owners
   bypass RLS unless forced); use `FORCE ROW LEVEL SECURITY`; set the variable
   inside the transaction so pooled connections never leak a previous tenant.
4. **Caches, queues, object storage, search indexes:** tenant id in every key,
   topic, prefix, or index routing.

### 6.3 Preventing cross-tenant access

- Authorization is always `(tenant_id from token, user_id, permission)`.
- Resource ids from the client are looked up **with** the tenant predicate
  (`WHERE id = ? AND tenant_id = ?`); not-found and forbidden look the same.
- Platform operators (your staff) use a **separate** realm role and an
  explicit, audited impersonation/"act as tenant" flow with a reason and
  expiry — never a bypass of the tenant filter.
- **Automated tests:** a cross-tenant suite creating two tenants and asserting
  every endpoint rejects tenant A's token against tenant B's resources;
  architectural tests that fail the build on repositories without the tenant
  predicate; RLS tests that connect as the app role with no tenant set and
  expect zero rows.
- Logs, metrics, and traces carry `tenant_id`; audit events for authentication,
  role changes, and admin actions.

### 6.4 Validation specifics

- Validate `iss`, `aud`, `exp`, and required claims (`tenant_id`, `sub`).
- Resolve the issuer through an **issuer allow-list** (Spring's multi-issuer
  resolver pattern) even with one realm today, so a future dedicated-realm
  tier needs no re-architecture.
- Never accept a Google-issued token directly; only Keycloak-issued ones.

---

## 7. User identity model

| Key | Stable? | Failure modes |
|---|---|---|
| `email` | **No** | Renames, aliases, reuse of an address by a different person after offboarding, case differences. Reuse could let a new hire inherit a predecessor's access. |
| `sub` alone | Yes | Unique, but carries no tenant scoping and no readable context; tenant must be stored separately anyway. |
| `tenant + email` | No | Inherits email problems; still unstable within the tenant. |
| **`tenant + sub`** | **Yes** | Stable across renames; a deleted-and-recreated account gets a new `sub` (new identity, no inherited access); tenant scoping explicit. |

### Recommendation

- Internal **`user_id`** (UUID) is the primary key and what other tables
  reference.
- **`UNIQUE (tenant_id, idp_subject)`**, where `idp_subject` is the Google `sub`
  as stored in Keycloak's federated identity (and/or the Keycloak user id).
- `email` is a **mutable attribute**, indexed, optionally unique per tenant for
  display and invitations — **never** used to authenticate, merge, or link
  accounts.
- Disable "link by email" in Keycloak's first-broker-login flow; match by
  federated identity only.
- A person with accounts at two customer orgs has two Google `sub` values and
  therefore two distinct identities, with no cross-tenant link.
- Offboarding: when an account is disabled/deleted in Workspace, disable the
  corresponding Keycloak user (sync or admin API) so address reuse cannot
  collide with a stale record.

---

## 8. Google Workspace group synchronization (optional feature)

### 8.1 Does each customer need to authorize the service account?

**Yes.** DWD is granted per Workspace: each customer's super admin must add
your service account's **Client ID** and the **read-only Directory scopes** in
*their* Admin console (Security → API controls → Domain-wide delegation).
There is no platform-side shortcut. Consider whether a **Google Workspace
Marketplace** listing (admin installs and approves scopes once) gives a smoother
onboarding than manual DWD configuration *(verify current Marketplace/DWD
requirements)*. An alternative that avoids DWD entirely is calling group APIs
with the *user's own* OAuth token, subject to its own scopes and visibility
rules *(verify)*.

### 8.2 Storing delegated admins and secrets

`tenant_integration` table (one row per tenant):

| Column | Notes |
|---|---|
| `tenant_id` | FK |
| `delegated_admin_email` | The real admin the service account impersonates. Config, not a secret — but access-controlled. **Validate its domain belongs to the tenant's verified domains** so one tenant cannot configure impersonation inside another's Workspace. |
| `status` | `pending` / `active` / `degraded` / `revoked` |
| `scopes_granted`, `last_verified_at`, `last_error` | Health and audit |

The **service-account key** is the real secret:

- Store in a KMS/secret manager, not in the repo or image; rotate regularly.
- Prefer keyless approaches where available (e.g. workload identity plus
  signing via the IAM Credentials API) to avoid long-lived keys *(verify)*.
- Blast radius: one service account with DWD reaches every connected customer.
  Isolate it in a dedicated project, grant read-only scopes only, restrict who
  can use it, alert on anomalous Directory API usage, and consider separate
  service accounts per region or tier.

### 8.3 Group → role mapping

```
tenant_group_mapping(tenant_id, google_group_id, google_group_email, role, created_by)
user_group_cache(tenant_id, user_id, google_group_id, synced_at)
```

- Tenant admins manage mappings in your admin UI (group → application role).
  Key by the group **id**, display the email (groups can be renamed).
- **Sync on login with a TTL cache**, plus an optional scheduled reconcile.
  Never call Google synchronously on every request.
- Effective roles = roles from mapped groups ∪ directly assigned roles;
  **default deny** if there is no mapping.
- Directory group listing by user returns direct memberships; nested groups
  need extra handling *(verify; decide whether nesting is in scope)*.
- **Fail closed:** if sync fails (DWD revoked, quota, outage), keep cached roles
  only until a hard expiry, then drop to no group-derived access; mark the
  integration `degraded` and surface it to the tenant admin.
- Roles live in the app database, not the JWT (§5.2), so changes take effect
  within the cache TTL.

---

## 9. Scalability analysis

| | 10 tenants | 100 tenants | 1000 tenants |
|---|---|---|---|
| **Single realm, shared IdP** | Trivial | Trivial | Fine. Load scales with users and logins, not tenants. Watch: user table size, login throughput, registry cache, Google Directory quotas. |
| **Single realm, IdP per tenant** | Fine | Login-page/IdP-list and admin overhead; many Google redirect URIs | Impractical: 1000 IdP configs and URIs to manage, plus Google URI limits *(verify)* |
| **Realm per tenant** | Fine, strong isolation | Painful: provisioning scripts mandatory, slower startup/admin console, upgrade migrations multiply, per-realm Google URIs | Generally impractical *(verify)*: very high memory/start-up/upgrade cost, 1000 URIs, multi-issuer backends everywhere |

Operational factors beyond Keycloak:

- **Onboarding effort:** shared IdP = a database row and a DNS check;
  per-realm/per-IdP = Keycloak provisioning plus a Google Cloud change.
- **Upgrades:** one realm migrates once; N realms migrate N times.
- **Backend:** single issuer is simplest; multi-issuer adds resolver logic,
  caching of N JWKS endpoints, and N sets of tests.
- **Tenant customization (branding, per-tenant MFA/session policy):** easier in
  realm-per-tenant; in a shared realm, deliver branding in your own app UI and
  policy in application logic, and reserve dedicated realms for tenants that
  truly require it.
- **Keycloak HA:** regardless of topology, run multiple nodes against a managed
  Postgres with a tuned session/cache setup; capacity-plan on logins per second.
- **Google quotas:** Directory API and OAuth rate limits are per project;
  plan sync scheduling and backoff.

---

## 10. Recommended production architecture

### 10.1 Logical architecture

```
                    ┌──────────────────────────────────────────────┐
                    │                Customer orgs                  │
                    │  acme.com    globex.com    contoso.com  ...   │
                    │  (Google Workspace each; own admins, 2SV)     │
                    └───────┬───────────────────────────────────────┘
                            │ OIDC (hd=*)                  ▲ DWD (per tenant,
                            ▼                              │  read-only Directory)
 ┌─────────┐   ┌───────────────────────────────┐    ┌──────┴───────────────┐
 │  SPA /  │──▶│ Keycloak (one realm, HA)       │    │ Group Sync Service    │
 │  Apps   │   │  shared Google IdP             │    │  SA key in KMS        │
 └────┬────┘   │  IdP-mapper tenant enforcement │    └──────┬───────────────┘
      │        │  mappers: tenant_id, aud       │           │
      │        └───────────┬───────────────────┘           │
      │                    │ registry lookup (API/cache)    │
      │                    ▼                               │
      │        ┌───────────────────────────────┐           │
      │        │ Tenant Registry / Control Plane│◀──────────┘
      │        │ tenants, domains, integrations │
      │        └───────────────────────────────┘
      │ Bearer JWT
      ▼
 ┌─────────────────────────────────────────────┐
 │ API services (Spring Boot resource servers)  │
 │  JWT -> TenantContext -> authz -> scoped data│
 └───────────────────┬─────────────────────────┘
                     ▼
        Postgres (tenant_id everywhere + RLS)  ·  cache/queue/storage (tenant-keyed)
```

### 10.2 Authentication sequence

```
User  SPA    TenantDir   Keycloak        Google     Registry     API
 │ email │       │           │              │           │          │
 │──────▶│ resolve domain    │              │           │          │
 │       │──────▶│ (uniform response)       │           │          │
 │       │ auth req (PKCE, kc_idp_hint=google, login_hint)         │
 │       │──────────────────▶│── redirect, hd=*, prompt ─▶│        │
 │◀──────────── Google sign-in (org policies, 2SV) ────────│        │
 │       │                   │◀── code, ID token (hd, sub, email) ─│
 │       │                   │── hd -> tenant? active? ───▶│       │
 │       │                   │◀── tenant_id / deny ────────│       │
 │       │                   │ find/create user by (google, sub)    │
 │       │                   │ set tenant_id, tenant_domain         │
 │       │◀── code ──────────│                                      │
 │       │── code+verifier ─▶│── access token (tenant_id, aud) ───▶ │
 │       │──────── Bearer ────────────────────────────────────────▶│
 │       │                                 validate · TenantContext · authz · scoped query
```

### 10.3 Data model (control plane + app)

```
tenant(tenant_id PK, name, status[pending|active|suspended|deleted],
       created_at, plan, data_region)

tenant_domain(domain PK, tenant_id FK, status[unverified|verified|revoked],
              verification_token, verified_at, last_reverified_at)

tenant_integration(tenant_id PK/FK, google_dwd_status, delegated_admin_email,
                   scopes_granted, last_verified_at, last_error)

app_user(user_id PK, tenant_id FK, idp_subject, email, display_name,
         status, created_at, last_login_at,
         UNIQUE(tenant_id, idp_subject))

membership(tenant_id, user_id, role, source[direct|group], PRIMARY KEY(tenant_id,user_id,role))

tenant_group_mapping(tenant_id, google_group_id, google_group_email, role)
user_group_cache(tenant_id, user_id, google_group_id, synced_at)

audit_event(event_id, tenant_id, actor_user_id, action, target, at, detail)

-- every business table: tenant_id NOT NULL, composite keys/FKs, RLS policy
```

### 10.4 Token and authorization model

- **Token:** `iss, aud, exp, sub, tenant_id, tenant_domain, email,
  email_verified, name, idp` (§5). ~5 min lifetime.
- **Authorization:** `can(user, action, resource)` evaluated as
  tenant from token → roles from `membership` (direct ∪ group-derived, cached)
  → resource fetched with tenant predicate → policy check. Tenant-admin
  actions (domain management, DWD setup, group mappings) require the
  `tenant_admin` role *within that tenant*. Platform-operator actions use a
  separate, audited path.

### 10.5 Onboarding a new customer domain

1. **Create tenant** (sales-led, or self-serve with safeguards). `status=pending`.
2. **Claim domain.** Tenant admin enters `acme.com`; platform issues a DNS TXT
   challenge. On verification → `tenant_domain.status=verified`.
   *Why DNS proof:* otherwise any employee of acme.com could sign in with
   Google, create a tenant for it, and become its admin. `hd` proves
   membership in the org, not authority over it.
3. **Activate tenant.** `status=active`. The registry now permits logins whose
   `hd` equals a verified domain.
4. **First admin signs in** through the normal flow; the platform grants
   `tenant_admin` to the user who completed the claim (or to a pre-invited
   email, matched by verified identity at first login — not trusted blindly).
5. **Optional: connect group sync.** Show the customer admin the service
   account **Client ID**, the exact scopes, and a field for the delegated admin
   email (validated to belong to their domain). A "Test connection" button
   attempts a Directory call and records `last_verified_at` / `last_error`.
6. **Configure group → role mappings** in the admin UI.
7. **Open to all users** at the domain; users sign in with no further setup.
8. **Offboarding / suspension.** Set `status=suspended`: the login flow denies
   new sessions, the API denies requests immediately (status check), Keycloak
   sessions for that tenant are revoked via the admin API, DWD integration is
   marked revoked, and data is retained or deleted per policy.

---

## 11. Risks and mitigations

| Risk | Mitigation |
|---|---|
| Tenant mis-resolution leaks data | Tenant only from validated token; composite keys; RLS; cross-tenant test suite |
| Self-service tenant takeover by a rogue employee | DNS ownership proof; admin approval; no auto-admin from `hd` alone |
| Expired/transferred domain gives a stranger access | Periodic re-verification; suspend on failure |
| User edits own `tenant_id` | Admin-only user-profile attributes in Keycloak |
| Link-by-email account takeover | Match by federated identity only |
| One DWD service account compromised | KMS/keyless, read-only scopes, dedicated project, monitoring, per-tier SAs |
| Stale roles after offboarding | 5-minute tokens, tenant status check per request, short group-cache TTL, fail-closed sync |
| Custom Keycloak SPI becomes a maintenance burden | Keep it minimal (lookup + attribute set); evaluate native Organizations support in newer Keycloak |
| Tenant enumeration via discovery endpoint | Uniform responses, rate limiting |

---

## 12. Verify before committing

> **Spike update:** item 1 (`hd=*`) is now verified against Keycloak 24.0.3's
> code, item 2 (Organizations) is confirmed absent in 24.0.3 (so it is not an
> option on this version), item 3 (redirect URI limit) is still inconclusive,
> item 4 (alias domains) is still open, and a related Keycloak `hd`-bypass
> advisory was found. See
> [multi_tenant_spike_plan.md](multi_tenant_spike_plan.md) for results and the
> remaining experiments. The list below is the original, unedited checklist.

I am confident about the overall shape; these details depend on current vendor
behavior and should be checked against documentation or a spike:

1. Keycloak's Google provider behavior with Hosted Domain `*` (Workspace-only,
   consumer Gmail rejected) on your target version.
2. Whether Keycloak (24 vs. newer) offers a native Organizations feature, and
   whether it is mature enough to replace the custom post-login SPI.
3. Google's limit on redirect URIs per OAuth client (supports the shared-IdP
   argument; the argument holds even if the limit is generous because of the
   operational cost per tenant).
4. Whether `hd` reports the primary domain for users on alias/secondary
   domains, and how Cloud Identity (non-Workspace) accounts behave.
5. Google consent screen/verification requirements for an External,
   multi-customer app, and Marketplace listing requirements as an alternative
   to manual DWD.
6. Directory API handling of nested groups and its quota model per project and
   per customer.
7. Practical limits for realm count in your Keycloak version (supports the
   realm-per-tenant analysis; treat the 1000-realm conclusion as directional).
8. Keyless service-account options for DWD signing in your cloud environment.

---

## 13. Suggested phasing

1. **Foundation:** single realm, shared Google IdP with `hd=*`, External consent
   screen, tenant registry, IdP-mapper enforcement, tenant attributes and
   mappers, short tokens.
2. **Backend isolation:** TenantContext filter, composite keys, ORM tenancy,
   RLS, cross-tenant test suite, audit log.
3. **Onboarding:** domain claim with DNS proof, admin UI, suspension flow.
4. **Group sync:** per-tenant DWD onboarding, mappings UI, cache, fail-closed
   behavior, health reporting.
5. **Enterprise tier:** dedicated realm/IdP option, multi-issuer routing,
   per-tenant policies.
