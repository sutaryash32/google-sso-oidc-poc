# Multi-Tenant SSO — Spike Plan & Results

Validates the assumptions in [multi_tenant_saas_design.md](multi_tenant_saas_design.md)
before implementation. Status as of this writing:

| # | Assumption | Status |
|---|---|---|
| 1 | Keycloak `hd=*` behavior | **Verified in code** (24.0.3 bytecode); runtime check with a consumer Gmail still pending |
| 2 | Alias / secondary domain handling of `hd` | **Open** — no documentation found; needs a live test |
| 3 | Post-login tenant validation in Keycloak | **Prototype built and validated against a mock IdP** (24 unit + 20 end-to-end tests) — see [test-harness/README.md](../test-harness/README.md). Implemented as a pre-provisioning IdP mapper rather than a post-login authenticator. Not yet run against real Google. |
| 4 | Multi-tenant DWD onboarding | **Open** — needs a second Workspace org |
| 5 | Redirect URI limits / large-scale onboarding | **Inconclusive** — sources conflict; shared-IdP design makes it moot |
| + | New: Keycloak Google-IdP `hd` bypass (CVE-2026-18214) | **Reviewed** — not exploitable in this setup as configured; see §6 |

---

## 1. `hd=*` behavior — verified from the Keycloak 24.0.3 jar

Method: extracted `org.keycloak.social.google.GoogleIdentityProvider` from the
running container's `keycloak-services-24.0.3.jar` and read its bytecode
(`javap -c`). Findings for `validateToken` (used on the ID token path):

| Configured Hosted Domain | Behavior |
|---|---|
| not set | **No `hd` check at all** — token accepted. |
| `*` | Token must **contain an `hd` claim**; any value accepted. Missing `hd` → `IdentityBrokerException: Identity token does not contain hosted domain parameter.` |
| `a.com` | `hd` must equal `a.com`, else `Hosted domain does not match.` |
| `a.com,b.com` | Value is split on `,` and matched with `List.contains` — **a comma list is supported in 24.0.3, but entries are not trimmed**, so `a.com, b.com` (with a space) would reject `b.com`. |

Also confirmed: `createAuthorizationUrl` adds `hd=<configured value>` to the
request to Google (matches the live redirect we captured earlier:
`hd=yserious.com`).

**Design implications**
- `hd=*` does reject accounts without `hd` (consumer Gmail), as designed.
- "Hosted Domain not set" would silently disable the check — never leave it
  empty in a multi-tenant realm.
- The multi-tenant design uses `*` plus the registry, so the comma/trim quirk
  is irrelevant to it.

**Still to run (runtime):** log in with a personal `@gmail.com` account against
a realm whose IdP has `hd=*`. Expected: Keycloak error page, no user created.

---

## 2. Alias / secondary domains — OPEN

Searches found Google's reference stating `hd` is the domain of the user's
Workspace/Cloud organization and that its absence means no hosted domain, and
that email domain is not sufficient to identify the org. **Nothing found says
which domain `hd` carries for a user on a secondary domain or domain alias.**

**Experiment (needs your Workspace + a second verifiable domain):**
1. In Admin console add a **secondary domain** (needs DNS TXT verification) and,
   separately, a **domain alias**.
2. Create `u1@secondary.example` and give an existing user an address at the
   alias domain.
3. Sign each in through the spike realm (`hd=*`) and decode the ID token
   (add an IdP mapper or log the brokered claims).
4. Record: `hd` value, `email` value, `email_verified`.

**Pass criteria:** `hd` is stable and equals one value per org (primary domain)
for all addresses → registry should map *all* of a tenant's domains to the same
`tenant_id` and key lookups by `hd` plus the verified-domain list.
**Fail/contrast:** `hd` follows the email's domain → registry lookup by `hd`
already works per domain; ensure every secondary domain is claimable.

---

## 3. Post-login tenant validation — PROTOTYPED (see ../test-harness/README.md)

> **Update:** built as an identity-provider mapper SPI instead of the
> authenticator described below, because the mapper's pre-provisioning hook
> avoids orphan users. Results: 24 unit tests and 20 end-to-end scenarios pass
> against a mock IdP. The original plan is kept below for reference.

Findings so far: no Organizations classes exist in 24.0.3's services jar and
none in `lib/lib/main`, so there is **no native tenant/organization feature to
rely on in this version**.

**Prototype plan: custom Authenticator SPI** in the post-broker-login flow
(Java, deployed as a jar into `/opt/keycloak/providers`):

1. Read the validated ID token from the brokered context; extract `hd`, `sub`,
   `email`, `email_verified`.
2. Resolve `hd → tenant` through a registry client (start with a static map or
   a small HTTP stub; production: control-plane API with a short TTL cache).
3. Deny with a clear page for unknown/suspended tenants.
4. On success set admin-only user attributes `tenant_id`, `tenant_domain`.
5. Add protocol mappers (user attribute → token claims) and an audience mapper.
6. Lock the attributes in the declarative user profile so users cannot edit
   them (account console and API).

**Test cases:** known tenant domain (pass); unknown Workspace domain (deny);
consumer Gmail (deny at the `hd` check); suspended tenant (deny); a user trying
to change `tenant_id` via the account console (blocked); token contains
`tenant_id`; backend rejects a token without it.

**Alternative to compare:** upgrade Keycloak to a version with Organizations and
evaluate whether it removes the need for the SPI. Decide after the prototype.

---

## 4. Multi-tenant DWD onboarding — OPEN

Needs a **second Workspace organization** acting as a "customer" (a free-trial
Workspace tenant, or Cloud Identity if it supports the needed admin APIs — check
before relying on it).

**Experiment:**
1. In the test org's Admin console, add the service account Client ID with the
   two read-only Directory scopes (same ones used today).
2. Store `delegated_admin_email` for that tenant; validate it belongs to that
   tenant's domain list.
3. Call `groups.list(userKey=<test user>)` impersonating that admin.
4. Negative tests: wrong admin email → expect `invalid_grant` (already seen
   with the placeholder admin); delegation not added → expect
   `unauthorized_client`; delegated admin from a *different* org → must be
   rejected by your validation before any Google call.
5. Revoke delegation mid-run → integration should flip to `degraded` and group
   roles should expire (fail-closed).

**Measure:** end-to-end onboarding time for a customer admin, number of manual
steps, and the quality of the error messages shown in the admin UI.

Also compare, as a time-boxed side experiment, a Google Workspace Marketplace
install flow versus manual DWD configuration.

---

## 5. Redirect URIs and large-scale onboarding — INCONCLUSIVE

Search results conflict: a third-party blog (WorkOS) states a limit of 100
redirect URIs per OAuth client; a Google Cloud Community answer says the OAuth
spec sets no hard limit; no official Google page quoting a number was found.

**Experiment (cheap, in a throwaway OAuth client):** keep adding distinct
redirect URIs of the form
`https://sso.example.com/realms/r{n}/broker/google/endpoint` until the Console
rejects one; record the count and error. Treat the answer as informational:
the recommended design uses **one** broker URI regardless of tenant count, so
the design does not depend on this limit.

**Other onboarding-scale checks:** time to create a tenant in the registry,
DNS-verification latency, Keycloak login latency with 1k–10k registry entries
(cache hit/miss), and Google Directory API quota behavior under a bulk sync.

---

## 6. Security finding: Keycloak Google-IdP `hd` bypass (CVE-2026-18214)

Per Red Hat's advisory page: in Keycloak's Google identity provider the normal
ID-token login validates `hd`, but the **external access-token (token
exchange) path does not**. Exploiting it requires the preview **Token
Exchange V1** feature and a confidential client with exchange permissions.
Rated Moderate (CVSS 6.8 per Red Hat). The advisory page does not list
affected/fixed versions; the page links Bugzilla 2508308 for that.

**Checked locally:** `KC_FEATURES` is not set on the POC container, so the
token-exchange preview is off by default. **Not verified:** the exact affected
and fixed version ranges — look them up before choosing a production version.

**Design takeaways**
- Never enable Token Exchange V1 on a realm that uses `hd` as a tenant
  boundary unless you are on a fixed version.
- This is a concrete example of why the design **must not rely solely on
  Keycloak's own `hd` check**: the registry check in the post-login step and
  the backend's own tenant validation are independent layers.
- Pin a patched Keycloak version in production and track advisories.

---

## 7. Proposed order of work

1. **Runtime confirmation of `hd=*`** (consumer Gmail rejected) — 30 minutes,
   spike realm only; no change to the working POC realm.
2. **SPI prototype** (§3) with a static registry — the biggest unknown.
3. **Alias/secondary-domain test** (§2) — needs DNS access to a second domain.
4. **Second-org DWD run** (§4).
5. **Redirect-URI limit probe** (§5) — optional.

**Isolation of the spike:** create a separate realm (e.g. `spike-mt`) so the
working `google-oidc-poc` realm is untouched. Note: a new realm means a new
broker redirect URI to register in the Google OAuth client
(`…/realms/spike-mt/broker/google/endpoint`) and the Google client secret
entered in that realm's IdP by you.
