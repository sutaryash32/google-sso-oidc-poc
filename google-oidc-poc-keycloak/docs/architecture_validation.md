# Architecture Validation — Multi-Tenant Google Workspace SSO

A critical review of the design in [multi_tenant_saas_design.md](multi_tenant_saas_design.md), written to find
failure cases rather than confirm it. Everything marked **Tested** can be reproduced with the scripts in
[../test-harness](../test-harness/README.md); everything else is labelled for what it is.

**Evidence labels used throughout**

| Label | Meaning |
|---|---|
| **Tested** | Run on the harness (real Keycloak 24.0.3, real tenant SPI, real backend and Postgres, **mock Google**). |
| **Code** | Read from Keycloak 24.0.3's own bytecode or from this repo's source; not exercised end to end. |
| **Docs** | From vendor documentation found while researching (linked). |
| **Reasoned** | Argued from how the systems work; nothing was run. |
| **Unknown** | Could not be established here; needs a spike. |

**Standing limitation.** There is no real Google sign-in in any of the tests. Mock Google issues the claims a scenario
needs, so the tests prove what *our* code does with a given token, not what Google actually puts in one.

---

## 1. Verdict in brief

> **Status update:** the required changes from §8.5 have since been implemented and tested, the real-Google spike is
> prepared, and two bugs were found in the first versions of the fixes. See §10 at the end of this document.

**Conditional approval.** The core shape holds up under attack: one shared realm, one shared Google IdP, tenant
resolved from Google's signed `hd` claim, a registry, tenant claims, and a backend that trusts only validated claims and
isolates data itself. **Do not start building on it unchanged.** The review found five weaknesses that need design
changes first (they are cheap now and expensive later):

1. **The user key is wrong.** The backend keys users on the *Keycloak* `sub`, which changes when a Keycloak user is deleted and re-linked (Tested). The Google subject is not in the token today, and the obvious Keycloak note that looks like it carries it actually carries the *email* (Tested). Assumption 10 does not hold as built.
2. **The default first-login flow can link a new person into an old account by email.** With SMTP configured, a new holder of a reused mailbox could verify by email and inherit the former employee's Keycloak user and data (Code; the flow options are present in both realms). The mitigation was tested.
3. **Suspension does not stop already-issued sessions.** Refresh tokens and SSO sessions keep minting tokens after a tenant is suspended (Tested). Only the backend's per-request check stops them. Revoking sessions on suspend closes it (Tested).
4. **Tenant identity is a domain, and domains change hands.** A lapsed and re-registered domain gives an attacker a "valid" tenant identity (Reasoned). Nothing in the design handles that.
5. **The tenant-resolution model is Google-shaped.** It generalizes to other providers only if the tenant key becomes "(provider, immutable org id)" and the SPI gains a provider adapter layer (Reasoned, with provider facts from general knowledge).

Five smaller items are listed in §7. §8 has the full verdict, spike list and required changes.

---

## 2. The ten assumptions

| # | Assumption | Status | Challenge and evidence |
|---|---|---|---|
| 1 | Google OIDC through Keycloak | **Holds** | Works for the yserious.com user; groups via DWD verified with a real token. |
| 2 | Multi-tenant SaaS model | **Holds, with caveat** | Needs the consent screen set to External (manual, unautomatable) before any other org can reach Keycloak. |
| 3 | One shared realm | **Holds** | Scales better than realm-per-tenant; isolation is logical, so the backend must carry it (it does: Tested). |
| 4 | One shared Google IdP | **Holds, with risks** | One OAuth client and secret for every customer: blast radius, quota, and any customer admin can block the app in their own Workspace (Docs/Reasoned, §7). |
| 5 | Hosted Domain `*` | **Holds, but is not a control** | Code: with `*` Keycloak rejects tokens that lack `hd`; with the field **empty it checks nothing**. It is a Google-side hint, not the boundary. |
| 6 | Tenant resolved from `hd` | **Mostly holds** | `hd` cannot be spoofed by the client (Tested) and consumer accounts are rejected (Tested). Open: what `hd` carries for alias/secondary domains (Unknown); domain re-registration (Reasoned, §5). |
| 7 | Domain-to-tenant registry | **Holds, with defects** | Works (Tested). Defects: unbounded staleness on read failure (Code), no public-suffix/free-mail guard until this review (fixed), file instead of an API. |
| 8 | JWT carries `tenant_id`, `tenant_domain` | **Holds, with a correction** | `tenant_id` is the key. `tenant_domain` is **not canonical** within a tenant: it carries whichever `hd` the user presented (Tested). Never key on it. |
| 9 | Backend trusts only validated claims | **Holds, but see #3 above** | Tested: tampered/forged/wrong-audience/no-tenant tokens rejected; tenant spoofing via header, query, body ignored. The per-request registry check is what makes suspension work. |
| 10 | Users unique on (tenant_id, provider, provider_subject) | **Does not hold as built** | The table keys on (tenant_id, Keycloak sub); `provider` is not stored; the Google subject is not in the token. See §5. |

---

## 3. A — Authentication validation

**Can a personal Gmail account authenticate?** No. A consumer account has no `hd` claim. Two independent layers reject it:
Keycloak's Google provider throws `Identity token does not contain hosted domain parameter` when Hosted Domain is `*`
(Code), and the tenant SPI denies with `MISSING_HD` (Tested). Not run with a real Gmail account (Unknown until the spike).

**Can a user from an unregistered Workspace domain authenticate?** They authenticate *at Google* (once the consent
screen is External) but cannot get a token: the SPI denies `UNKNOWN_DOMAIN` before any Keycloak user is created
(Tested, 403, no code issued, no user). Today the Internal consent screen also stops them at Google.

**Can a user from a registered domain authenticate?** Yes, if the tenant is active and SSO-enabled, the email's domain
belongs to the same tenant, and any discovery hint agrees (Tested, including secondary-domain emails).

**What exact claim proves Workspace membership?** `hd`, and only `hd`. Google's reference says `hd` is present only when
the user belongs to a Google Cloud organization, and warns that the email domain alone is insufficient to establish
that ([OIDC reference](https://developers.google.com/identity/openid-connect/reference),
[verify an ID token](https://developers.google.com/identity/gsi/web/guides/verify-google-id-token)) (Docs).
Tested: a consumer Google account registered with a corporate address (`ceo@acme.com`, `email_verified=true`, no `hd`)
is rejected, so `email` and `email_verified` prove nothing about organization membership.
*Nuance:* "Google Cloud organization" also covers **Cloud Identity** orgs that have no Workspace licences, so `hd` proves
"managed Google organization", not specifically "Workspace".

**When can `hd` be missing?** Consumer accounts, including Gmail and non-Gmail addresses registered as personal Google
accounts ("unmanaged" accounts) (Docs, Tested for the unmanaged case). Any other case is Unknown; treat absence as deny,
which the SPI does.

**Can `hd` be spoofed by the client?** Not through the request: a client-supplied `hd=acme.com` is ignored and the
consumer account is still denied (Tested). The value that counts is inside the ID token Keycloak receives from Google's
token endpoint. **Residual risk (Code, read from the real realm's IdP config):** the Google IdP has `validateSignature`,
`issuer` and PKCE all unset. The token is trusted because it arrives over TLS directly from Google with the client
secret, which the OIDC spec allows, but there is no second line of defence if that channel is ever intercepted.
Enabling signature validation (Google's JWKS), the issuer check and PKCE is recommended, and **must be spiked against
real Google first** because it could break sign-in if mis-set.

---

## 4. B — Multi-provider generalization

**Verdict:** the model generalizes only if the tenant key changes from *a domain* to *(provider, immutable
organization id)*, and the SPI gains an adapter per provider. Provider facts for Entra, Okta and SAML below are from
general knowledge and were **not** re-verified against current documentation here; check them before relying on them.

| | Google Workspace | Microsoft Entra ID | Okta | Generic SAML |
|---|---|---|---|---|
| Shared IdP possible? | **Yes** (one OAuth client) | Yes (multi-tenant app registration) | **No**: one IdP per customer org | **No**: one IdP per customer |
| Immutable org key | `hd` (a domain: can lapse or move) | `tid` claim (tenant GUID, immutable) | The IdP itself (its issuer / alias) | The IdP itself (entityID / alias) |
| Immutable user key | `sub` (global, stable) | `oid` + `tid` (`sub` is pairwise per app) | `sub` (stable) | NameID: format-dependent, may be transient |
| Email trustworthy? | `email_verified`, but not org proof | **No**: `email` is optional and unverified for authorization | Per-customer policy | **No**: attribute is whatever the IdP sends |
| Example org claim | `"hd": "acme.com"` | `"tid": "72f988bf-86f1-41af-91ab-2d7cd011db47"` | `"iss": "https://acme.okta.com"` | `<Issuer>https://idp.acme.com/saml</Issuer>` |
| Tenant resolved by | registry lookup on `hd` | registry lookup on `tid` | **IdP alias → tenant binding** | **IdP alias → tenant binding** |

**Would the SPI need provider-specific logic?** Yes: *which claim carries the org key, and how trustworthy it is*,
differs per provider. **Tenant-registry lookups?** Yes, but keyed `(provider_type, org_key)`, not by domain; for
Okta/SAML the key is the Keycloak IdP alias. **Claim normalization?** Yes: every provider should be reduced to one record

```
IdentityFacts { providerType, idpAlias, issuer, orgKey, orgKeyKind, subject, email, emailVerified }
```

before any tenant logic runs. Today's `TenantResolver.Input` is Google-shaped (`hd`, `email`, `emailVerified`, hint).
A refactor into `ProviderAdapter -> IdentityFacts -> TenantResolver` is small, but it should happen **before** a second
provider is added, and the registry schema should become `tenant_idp_binding(provider_type, org_key, tenant_id,
status)` with domains kept only for discovery and the email cross-check.

Two corollaries: with per-customer IdPs (Okta, SAML) the Keycloak IdP alias *is* the trust anchor, so **creating an IdP is a
privileged operation** that must be tied to a verified tenant; and "email domain to tenant" must never be used for
those providers, because the customer controls what email the IdP asserts.

---

## 5. C — Trying to break tenant isolation

| Attack or edge case | Result | Evidence |
|---|---|---|
| Cross-tenant API access with another tenant's token | Blocked: 404, not 403 | **Tested** (backend e2e) |
| Tenant spoofed in header, query string or body | Ignored | **Tested** |
| Client-supplied `hd` | Ignored | **Tested** |
| Forged email domain: `hd=acme.com`, email at another tenant | Denied `EMAIL_DOMAIN_MISMATCH` | **Tested** |
| Consumer account with a verified corporate email | Denied `MISSING_HD` | **Tested** |
| Look-alike domains (`acme.com.evil.com`, `mail.acme.com`, case) | Exact match only: denied / normalized | **Tested** |
| Secondary-domain user (email on `acme.co.uk`, `hd=acme.com`) | Allowed, maps to the tenant | **Tested** (mock) |
| `hd` reports a secondary domain | Allowed, maps to the same tenant; `tenant_domain` then differs between users of one tenant | **Tested** (mock) |
| What `hd` actually carries for secondary/alias domains in real Google | Unknown | **Unknown**, needs a live Workspace with a secondary domain |
| Renamed email, same Google `sub` | Same Keycloak user, tenant unchanged; email updated, username stays the old address | **Tested** |
| Deleted and recreated account (new `sub`, same email) | **Blocked on Keycloak's "Account already exists" page**; the user is stuck without admin help | **Tested** |
| ...same, with SMTP configured | The default flow offers "Verify existing account by Email": the new mailbox owner can link into the **old** user | **Code** (both realms have the option; no SMTP here to run it) |
| Disabling "Handle Existing Account" | The link offer becomes a hard 400; a legitimate returning user still signs in | **Tested** |
| Keycloak user deleted and re-linked (admin clean-up) | Keycloak `sub` changes (new UUID); the Google subject does not | **Tested** |
| Provider subject via a "user session note" mapper | The note holds the **username (email)**, not the Google `sub`: an email-keyed identity if used naively | **Tested** |
| Tenant domain moves between tenants | Existing users denied `USER_TENANT_CONFLICT` until an admin resolves it (safe, but an outage) | **Tested** |
| Tenant suspended: new sign-in | Denied | **Tested** |
| Tenant suspended: refresh token | **Still mints tokens** | **Tested** (gap) |
| Tenant suspended: existing SSO session | **Still issues codes silently** | **Tested** (gap) |
| Revoke the tenant's sessions on suspend | Refresh and silent re-auth both fail | **Tested** (fix) |
| Domain lapses and an attacker re-registers it, then creates a Workspace | Their `hd=acme.com` accounts map to Acme's tenant: **cross-tenant takeover** | **Reasoned**, not testable here |
| Registry unreadable after load | SPI and backend keep the **last good snapshot forever**: a suspension made while the registry is unreachable is never seen | **Code** |
| Admin API compromise | Anyone who can write user attributes can forge `tenant_id` | **Reasoned** |
| Google group addresses / shared mailboxes | Groups cannot authenticate; a *user's alias* may sign in as the primary account (which address appears in `email` is Unknown) | **Reasoned / Unknown** |
| Linking an account from Keycloak's account console | Whether the mapper runs on that path is untested | **Unknown** |

**The failure that matters most is domain re-registration.** `hd` proves membership of whoever currently controls
that Google organization. It does not prove continuity with the organization you onboarded. Mitigations to design in:
periodic DNS re-verification (a failed check suspends the tenant); requiring an admin invitation or approval for
*new* users after the tenant's first N days rather than pure just-in-time provisioning; alerting on a sudden surge of
first-time users from one tenant; and, where DWD is configured, pinning the tenant to Google's stable Workspace
customer ID (obtainable through the Directory API, not present in the ID token).

---

## 6. D — Where should the SPI run?

| Extension point | Runs when | Verdict |
|---|---|---|
| **IdP mapper, `preprocessFederatedIdentity`** (built) | Every brokered login, **before** any user is created or linked; sees the validated ID token | **Best for enforcement.** Code: called in `IdentityBrokerService.authenticated`, ahead of the first-login flow. Tested: denials leave no user. Cons: Keycloak marks the mapper SPI *internal*; the user sees a generic 403 |
| Custom authenticator in **First Broker Login** | Only the first time a user signs in | Insufficient alone: existing users, and anything that changes later (suspension), are never re-checked. It would also sit where users are created (`Create User If Unique`), so placement matters |
| Custom authenticator in **Post Broker Login** | After user creation and linking | Wrong place to *enforce*. Code: `UserProvider.addUser` runs inside the first-login flow and `importNewUser` in `afterFirstBrokerLogin`, with the post-login flow after, so a denial here would leave an orphan user. Reasoned from that order; not run |
| **Protocol mapper** | Every token issuance, **including refresh** | Right place to **emit** claims (done, with attribute mappers). A custom one could also **re-check the registry on every refresh**, closing the suspension gap at the source. Cannot see the Google token; whether throwing there cleanly aborts issuance is **Unknown** (spike) |
| Event listener | After the fact, asynchronous | Audit and alerting only; cannot block |
| Client policy executors | Token endpoint events | Possible home for a refresh-time check; **Unknown** (spike) |

**Recommended approach: layered, not a single hook.**

1. **IdP mapper** enforces tenant resolution at login and stamps admin-only attributes: `tenant_id`, `tenant_domain`, and (new) `idp_alias` and `idp_subject` (the provider's subject, taken from the brokered context, not from a session note).
2. **Attribute protocol mappers** emit `tenant_id`, `idp`, `idp_sub` (and `tenant_domain` for display only).
3. **A custom first-broker-login flow** that links *only* by federated identity and never by email (mitigation Tested).
4. **Session revocation when a tenant is suspended or its domain changes** (Tested), plus a token-time re-check as a spike.
5. **Backend per-request registry check** stays as the authoritative last line (Tested).

Against the six responsibilities you listed: reading claims (done); determining the provider type (**not done**: the SPI is Google-only);
resolving the tenant (done); rejecting unknown tenants (done); adding `tenant_id` and `tenant_domain` (done, but by
attribute mappers, not by the SPI itself, which is the cleaner split); allowing issuance (done).

---

## 7. E — Production readiness

**Hidden assumptions**
- `hd` is a stable organization identity (it is a domain: see §5).
- JIT provisioning is acceptable: every person in a verified domain becomes a user. Fine for a legitimate domain, dangerous after a takeover.
- The Keycloak admin API and console are trusted: they can set `tenant_id`.
- One person has one Google account per organization, and email is unique per realm over time (it is not: reuse).
- The registry file is available and current for both readers.

**Shared Google IdP**
- One client secret for every customer: rotating it affects all tenants at once; leaking it affects all.
- Any customer's Workspace admin can block the app for their organization; their users then fail at Google, and from your side this looks like an outage with no signal.
- External consent screen: brand/verification requirements and quotas apply to the whole platform (check current rules: one source in this review found no official per-client redirect URI limit, a third-party source claimed 100, so the number is unconfirmed, but the shared IdP uses one URI regardless).
- Per-tenant policy (session lifetime, MFA) cannot differ in a shared realm.

**Shared service account for DWD**
- One key reaches every connected customer's directory (read-only scopes, but all of them). Hold it in a KMS or use keyless signing, rotate it, monitor Directory API use, isolate it in its own project.
- Domain-wide delegation lets the account impersonate *any* user in an authorizing domain. The backend only ever impersonates the registry's `groupsDelegatedAdmin`, and refuses an admin outside the tenant's own domains (Tested), but that rule is the only thing standing between a registry mistake and cross-tenant impersonation.
- Each customer must authorize the Client ID themselves; revocation is invisible until a call fails.

**DNS ownership verification** is necessary and **not sufficient**: it proves control at onboarding, not continuity, and it is not automated yet. Also needed: a public-suffix check (the CLI accepted `co.uk`, now rejected by a heuristic; a real Public Suffix List is required in production), a free-mail blocklist (added), reserved-domain rules, and re-verification.

**Onboarding workflow risks**
- Self-service tenant creation lets any employee of acme.com claim acme.com first unless DNS proof gates it.
- Who becomes the first admin must be decided by the verified claimant, never by "first to sign in".
- Adding a secondary domain is a manual registry change; until then those users get `UNKNOWN_DOMAIN`. Domain changes are an outage-prone operation without a self-service flow.

**Alias and multiple domains**
- Uniqueness of `domain -> tenant` is enforced by the CLI and, defensively, at login (an ambiguous domain is denied), but not transactionally: a real registry needs a unique constraint.
- Removing or moving a domain strands existing users (`USER_TENANT_CONFLICT`): correct, but it needs a runbook.

**Scalability and operations**
- Realm count is not the issue; the file registry is: two readers, no versioning, unbounded staleness.
- Keycloak mapper SPI is internal: pin the version and run the harness on every upgrade.
- Only denials are logged, with reasons; there are no metrics or alerts.
- The user-facing denial is a generic 403 for every reason.

**Defects found in this repository during the review**
1. `tenant.mjs suspend` claimed sessions "end when tokens expire". False (Tested). **Fixed**: it now revokes the tenant's Keycloak sessions.
2. The CLI accepted `co.uk`. **Fixed** (heuristic); needs a real Public Suffix List later.
3. Registry readers keep a stale snapshot forever. **Open.**
4. Backend keys users on the Keycloak `sub`. **Open.**
5. Google IdP has no signature validation or PKCE. **Open, needs a spike on real Google.**
6. First-login flow can link by email. **Open** (mitigation tested on the harness, not applied to your realm).

---

## 8. F — Final verdict

**1. Validated (Tested or Code)**
- Tenant resolution from a signed `hd`: unknown, suspended, SSO-disabled, missing-`hd`, unverified-email, mismatched-email, mismatched-hint, ambiguous-domain and conflicting-user logins are all denied before any user exists (20 scenarios).
- The client cannot supply or influence `hd`; a verified corporate email without `hd` is rejected.
- Backend isolation: audience, tenant claims, per-request registry check, tenant-scoped data with row-level security, tenant spoofing ignored (45 backend tests, 17 end-to-end checks).
- Renamed email keeps the same user; secondary-domain emails map correctly; tenant moves are denied safely.
- Revoking sessions on suspend closes the refresh/SSO gap; disabling email-based linking closes the reuse-takeover path.
- Pre-provisioning is the right enforcement point (Code).

**2. Still assumptions**
- Real Google behavior of `hd=*`, including that a real Gmail account is rejected.
- What `hd` carries for alias and secondary domains; what `email` carries when signing in through an alias.
- That Keycloak's Google provider honors `validateSignature` and PKCE.
- That the identity-provider mapper also covers linking from the account console, and token exchange.
- Whether a protocol mapper or client policy can cleanly deny a refresh.
- Providers other than Google: facts above are unverified.
- Multi-tenant DWD onboarding end to end.

**3. Must be proven through a spike** (ordered by risk, with pass criteria)

| Spike | Pass criteria |
|---|---|
| Real Google sign-in against a copy of the realm with `hd=*` and the SPI | A yserious.com user signs in; a personal Gmail is refused with no Keycloak user created |
| Signature validation + PKCE on the Google IdP | Real sign-in still works with both on; a token with a bad signature is refused |
| Alias / secondary domain `hd` and `email` in real Google | Documented values for a primary domain, secondary domain and alias; registry rules confirmed or changed |
| Refresh-time tenant check (custom protocol mapper or client policy) | A suspended tenant's refresh is refused with no session revocation; no token is issued |
| Custom first-broker-login flow (no email linking) on the real realm | Recreated account is denied cleanly; returning user unaffected; admin recovery path documented |
| Second Workspace + DWD onboarding | Customer-admin steps timed; failure modes (`unauthorized_client`, `invalid_grant`) surfaced to the tenant admin |
| Stamping and emitting `idp_subject` | Token carries the Google subject; it survives deleting and re-linking the Keycloak user |

**4. Would I approve it for implementation?** Yes, **conditionally**: the architecture is sound and the enforcement point is
right. Not for production until the spikes above pass and the changes below are made. The riskiest unproven item is
real Google sign-in, which nothing so far has exercised.

**5. Changes before development starts**
1. **Make the identity key the provider subject.** Stamp `idp_alias` and `idp_subject` from the brokered context in the SPI, emit them as claims, and key the app database on `(tenant_id, idp_alias, idp_subject)`. Do not use the Keycloak `sub` or the session-note mapper.
2. **Replace the first-broker-login flow** with one that links only by federated identity, never by email, and routes email conflicts to an admin runbook.
3. **Revoke a tenant's sessions on suspend or domain change** (done in the CLI; move it into the control plane) and spike a refresh-time check.
4. **Bound registry staleness** (fail closed after a maximum age) and replace the file with a control-plane API with unique constraints, versioning and an audit trail.
5. **Add domain-takeover controls:** periodic DNS re-verification, a policy for onboarding new users after the first period, new-user-surge alerting, and optional customer-ID pinning where DWD exists.
6. **Introduce `IdentityFacts` and a provider adapter layer** and change the registry to `(provider_type, org_key)` before adding any second provider. Keep domains for discovery and the email cross-check only.
7. **Harden the Google IdP** (signature validation, issuer, PKCE) after the spike.
8. **Treat `tenant_domain` as display-only** everywhere; document that `tenant_id` is the only key.
9. **Operationalize:** metrics and alerts on denials by reason, a tenant-friendly denial page, a runbook for domain changes and recreated accounts.

---

## 9. Reproducing the evidence

```powershell
cd google-oidc-poc-keycloak\test-harness
docker compose up -d --build ; node mock-idp\server.mjs     # in another terminal
node scripts\setup-realm.mjs
node scripts\e2e.mjs            # 20 scenarios: does the design enforce what it claims
node scripts\e2e-attacks.mjs    # adversarial and lifecycle cases: records OK / GAP / INFO
```

`e2e-attacks.mjs` currently reports 12 observations: 6 OK, 5 GAP, 1 INFO. The five GAPs are findings 1 (twice, the
subject and the sub instability), the recreated account, and the two suspension gaps. They are expected to stay GAPs
until the changes in §8.5 are made; the script records behavior, it does not fail the build.

---

## 10. Follow-up: the required changes, and the real-Google spike

Written after the review above, once these were agreed as mandatory before implementation. **Status first, then evidence.**

| Mandatory item | Status |
|---|---|
| Stable provider subject strategy | **Implemented and tested; applied to the real realm and the real application database** |
| Removal of email-based account linking | **Implemented and tested on the harness; not yet applied to the real realm** (`enable-multitenancy.mjs --harden`) |
| Tenant-wide session revocation on suspension | **Implemented and tested** (the CLI revokes sessions; a token-time guard also refuses tokens without any revocation); the guard is not yet applied to the real realm |
| Real Google Workspace login | **Prepared and dry-run; waiting for your sign-ins** ([google_spike_runbook.md](google_spike_runbook.md)) |
| Personal Gmail rejection | **Prepared; waiting for your sign-ins** (two runs, so each layer is seen refusing it separately) |
| Alias / secondary domain behaviour | **Prepared; waiting for your sign-ins and, for secondary domains, a domain you can verify** |

Also closed from the review: the registry staleness bound is now enforced in **both** readers (the Keycloak plugin and the backend).

### 10.1 What was built, and the evidence

**Stable provider subject.** The plugin stamps `idp_alias` and `idp_subject` (the provider's own subject, taken from the brokered
login, not from a session note) as admin-only attributes; attribute mappers emit them as the `idp` and `idp_sub` claims; the
backend requires both and keys users on `(tenant_id, idp, idp_sub)`. A recorded subject that differs from the one presented is
refused (`USER_IDENTITY_CONFLICT`).
- Tested: the harness suite (21 scenarios) checks that `idp_sub` equals the provider's subject and differs from Keycloak's own
  `sub`, that the attributes are stored, that writing them through the account API is rejected, and that a mismatched recorded
  subject is refused. The adversarial suite shows `idp_sub` survives deleting and re-linking the Keycloak user (Keycloak's `sub`
  changes). The backend suite shows the **same application user** after the Keycloak user is deleted and re-created.
- Applied to the real stack: realm attributes and mappers, a back-fill of the existing user, and a transactional migration of the
  existing `app_user` row (`scripts/migrate-provider-subject.mjs`, dry run first; the application user id was preserved). The
  real token now carries `idp=google-oidc` and a 21-digit numeric `idp_sub`. That is the first real Google subject observed, but
  it was read from Keycloak's federated-identity link, not from a live sign-in.

**No email-based linking.** A copy of Keycloak's first-login flow with "Handle Existing Account" removed and a "deny existing
account" step in its place (`NoEmailLinkAuthenticator`).
- Tested (adversarial suite): a recreated Google account (new subject, same email) gets a 403, the reason
  `EXISTING_ACCOUNT_NOT_LINKED` is logged, the old Keycloak user is untouched and no user is added; a renamed email with the same
  subject still signs in.
- **A bug in my first version, found by reading the created flow rather than trusting the run:** Keycloak renames a copied
  flow's subflows with the copy's name as a prefix, so my exact-name match missed "Handle Existing Account". The email-link path
  was still there and my deny step sat after it, so nothing was protected. Fixed (match by suffix) and re-verified.

**Tenant-wide revocation on suspension.** Two independent mechanisms:
1. `tenant.mjs suspend` revokes the tenant's Keycloak sessions (tested: sessions 1 -> 0).
2. `TenantGuardMapper`, a token-time guard, refuses to issue any token (including on refresh and silent re-authentication) for a
   tenant that is unknown, suspended or SSO-disabled, with no revocation needed. Tested: after suspension a refresh returns
   `400 invalid_grant`, and a silent SSO re-authentication gets a code but **no token**; after re-activation a fresh sign-in works.
- **Another bug in my first version:** the guard did nothing. Keycloak's base mapper class only calls the hook when the mapper is
  flagged "include in access token", and I had set no such flag. Worse, an administrator unticking that flag would have silently
  disabled the guard. Fixed by overriding the token hooks so the check always runs, then re-tested.

**Staleness bound (both readers).** A registry snapshot is trusted only while it is known to be current. If the file is unreadable
or corrupt, the last snapshot is served for at most 15 minutes (`TENANT_REGISTRY_MAX_STALENESS_SECONDS`), then every tenant is
unknown. Tested on both sides with an injectable clock.

**Numbers on the final code:** plugin 35 unit tests; backend 51 (11 against the real Postgres schema); harness suite 21/21;
adversarial suite 13 observations (12 OK, 0 GAP, 1 INFO); backend end-to-end suite 17/17 (the slow expiry check was skipped).

### 10.2 The real-Google spike: what is ready, what is not proven

Ready, and dry-run with deliberately fake credentials: the `spike-google` realm (real Google IdP, Hosted Domain `*`, signature
validation, issuer check, PKCE, claim logging), a receiver that catches a sign-in and prints the token's claims, an observer that
reads Keycloak's log and says which layer accepted or refused each account, and the runbook. The dry run confirmed the
**outbound** request: Keycloak sends Google the spike's own redirect URI, `hd=*`, `prompt=select_account` and a PKCE S256
challenge. A code check confirmed that Keycloak's Google provider extends the generic OIDC provider, overrides only the `hd`
check, and leaves the validated ID token where the tenant plugin reads it.

**Still unproven, because it needs a live Google sign-in:** that real Google tokens validate with signature and issuer checking on
(and that the check is truly active); what `hd`, `email` and `sub` look like for aliases and secondary domains; the real refusal of
a personal Gmail by each layer; and the plugin's behaviour on a real (not mock) token end to end.

### 10.3 What is deliberately not applied to your real realm yet

`--harden` (no email linking, token-time guard) and any Google IdP hardening. The first two are validated on the harness; I would
apply them once the real-Google spike has shown the flow behaves the same with a genuine Google identity.
