# Hub-and-spoke proof of concept: master realm -> shared Google IdP -> `yserious` realm

**Status.** Built and running for the tenant realm `yserious`: the chain, plus a **tenant gate** added afterwards (see the
update below). Scope: prove the architecture before more tenants; no domain-wide delegation, no group sync. Larger context:
`google_hub_and_spoke_design.md`. The sections below are the original minimal plan; where they differ from the update, the
update wins.

**Update: tenant gate and `setup-tenant.mjs`.** The original plan relied on master's Hosted Domain for the tenant check. That
cannot survive a second tenant, so each tenant realm now has a gate: `hub-tenant-gate-mapper` (in `tenant-spi/`), attached to
the realm's `google-hub` IdP, runs before any user is created and requires (1) Google's `hd` as passed through master, (2) a
verified email and (3) an email domain that all belong to the domains bound to the realm (`allowed.domains` on the mapper,
written by `--domain`), plus a Google subject and no conflicting subject for an existing user. Every missing claim is a
denial. To carry what the gate needs, the chain now propagates three attributes through both hops: `google_hd`, `google_sub`,
`google_email_verified`. `scripts/setup-tenant.mjs --id <realm> --domain <d>` replaces the earlier single-tenant script: it
sets up the shared hub once and one tenant per run; `--check` reports whether a tenant and its gate are in place; master's
Hosted Domain starts restricted to the first tenant's domain and is changed only by `--hosted-domain` (`'*'` is the later step,
to be taken after the gate is proven with real Google). A realm whose gate mapper is missing admits whatever master admits, so
`--check` belongs after any change to a realm.

**Update: master gate and per-realm backend.** (1) The same gate now also sits on master's own Google IdP, reading Google's raw
claims (`claim.prefix=raw`, `gate.name=master`) and bound to the union of every tenant realm's domains, which `setup-tenant.mjs`
recomputes from the realms on every run and on `--revert`. A foreign organization is refused at master and no user is created
there; an empty union denies everyone. What it cannot do: a REAL tenant's account sent to the wrong tenant's realm is admitted by
master (its own tenant owns that person) and refused by that realm's gate, so master keeps a record for it. (2) The backend no
longer validates one issuer. It trusts the `issuer` of each tenant in the registry (keys from `<issuer>/protocol/openid-connect/certs`),
contacts no other issuer, and accepts a realm's tokens only for the tenant bound to that issuer: the `tenant_id` claim is written by
whoever administers the realm, so a realm that claims another tenant's id gets `403 issuer_mismatch`. The legacy single issuer
(`TENANT_ISSUER`) remains optional. Not yet done: the frontend is fixed to one realm (a tenant-selecting login is a UI task),
and the tenant claims in the app token are still realm constants rather than being derived from the issuer.

Keycloak stays at 24.0.3 (no feature here needs a newer one). Items marked **[verify]** are Keycloak behaviours I have not
yet run in this chain.

## 1. Architecture

```
 Browser (SPA, localhost:5173)
    |  1. login, kc_idp_hint=google-hub
    v
 Realm  yserious            (issues the app JWT; iss = .../realms/yserious)
    |  2. IdP "google-hub"  (keycloak-oidc: yserious acts as an OIDC client of master)
    v
 Realm  master              client "broker-for-yserious"
    |  3. IdP "google"      (the ONE shared Google IdP)
    v
 Google Workspace (yserious.com)         Google Cloud project/client: the existing ones, reused
```

Return path: Google -> master (`/realms/master/broker/google/endpoint`) -> master issues a code to
`yserious` (`/realms/yserious/broker/google-hub/endpoint`) -> `yserious` creates the user and issues **its own** JWT to the SPA.
The backend only ever sees a `yserious` token.

## 2. Keycloak objects (minimum)

**Master realm**

| Object | Detail |
|---|---|
| IdP `google` | Provider `google`; the **existing** Google client id/secret; Hosted Domain `yserious.com`; `prompt=select_account` |
| IdP mappers on `google` | `hd` -> user attribute `google_hd`; `sub` -> user attribute `google_sub` |
| Client `broker-for-yserious` | Confidential; valid redirect URI `http://localhost:8280/realms/yserious/broker/google-hub/endpoint` only |
| Client mappers on it | User attributes `google_hd`, `google_sub` -> token claims of the same names |
| User profile | `google_hd`, `google_sub` declared (Keycloak 24 drops undeclared attributes) |

**`yserious` realm**

| Object | Detail |
|---|---|
| IdP `google-hub` | Provider `keycloak-oidc`; authorization URL `http://localhost:8280/realms/master/protocol/openid-connect/auth?kc_idp_hint=google`; client id `broker-for-yserious` and its secret |
| IdP mappers on `google-hub` | Claims `google_hd`, `google_sub` -> user attributes of the same names |
| Client `google-oidc-poc-frontend` | Same id as today; redirect URI/origin `http://localhost:5173`; the existing audience mapper (`oidc-poc-api`) |
| Client mappers | `google_sub` attribute -> claim `idp_sub`; constants `tenant_id=t-yserious`, `tenant_domain=yserious.com`, `idp=google` |
| User profile | `google_hd`, `google_sub` declared |

The constants are a **proof-of-concept shortcut** so the existing backend validators (which require `tenant_id`,
`tenant_domain`, `idp`, `idp_sub`) keep working. In real hub-and-spoke the tenant is the issuer, so those constants go away.

## 3. The three questions

- **Broker client required? Yes.** The `google-hub` IdP is an OIDC client of master, and an OIDC client needs a registered client
  on the server. It is also what restricts where master may send the user back (its redirect URI).
- **`google-hub` IdP required? Yes.** It is the thing that makes `yserious` delegate login to master instead of to Google. Without
  it `yserious` would need the Google IdP itself, which is the current POC.
- **Organization required? No.** Azure uses one for inventory; routing uses `kc_idp_hint`. With one tenant it adds nothing, and it
  would force a Keycloak 26 upgrade. Skip it.

## 4. Authentication sequence

1. SPA calls `keycloak.login` against realm `yserious`, with the IdP hint `google-hub`. (Frontend changes: realm name and the
   hint value.)
2. `yserious` sees the hint and redirects the browser to master's authorization URL, with `client_id=broker-for-yserious` and
   `redirect_uri=.../realms/yserious/broker/google-hub/endpoint`; the URL already carries `kc_idp_hint=google`.
3. Master validates the client and redirect URI, sees `kc_idp_hint=google`, and redirects the browser to Google
   (`redirect_uri=.../realms/master/broker/google/endpoint`, `hd=yserious.com`).
4. User signs in at Google (the Internal consent screen already limits this to the organization).
5. Google returns a code to master's broker endpoint. Master exchanges it, validates the ID token, creates or finds a **master**
   user, and runs the `google` IdP mappers (`google_hd`, `google_sub`).
6. Master issues its own code to `yserious`'s `google-hub` endpoint.
7. `yserious` (server-side) exchanges the code at master's token endpoint, receives a master token containing `google_hd` and
   `google_sub`, and runs the `google-hub` mappers into the **`yserious`** user.
8. First login runs the realm's first-broker-login flow and creates the `yserious` user. Later logins find it by the link.
9. `yserious` issues the code/tokens to the SPA; the JWT has `iss=.../realms/yserious`, `idp_sub`, and the constants.

**How the user lands in `yserious`.** The user is never "moved" between realms. `yserious` is the OIDC *client* that started
the login; master is the OIDC *server* it chose to delegate to. Every redirect carries the originating `yserious` redirect URI,
and master can only return to the one registered on `broker-for-yserious`. The user ends up with a session and a user
record in `yserious`, and tokens signed by `yserious`.

## 5. Redirect URIs (three places)

| Where | URI |
|---|---|
| **Google Cloud** (existing OAuth client, authorized redirect URIs) | **Add** `http://localhost:8280/realms/master/broker/google/endpoint`. Keep the current `.../realms/google-oidc-poc/broker/google-oidc/endpoint` until the old realm is retired |
| **Master** client `broker-for-yserious` | `http://localhost:8280/realms/yserious/broker/google-hub/endpoint` |
| **`yserious`** client `google-oidc-poc-frontend` | `http://localhost:5173/*` and web origin `http://localhost:5173` (as now) |

## 6. Reusing the Google Cloud project and OAuth client

Nothing is created in Google Cloud: same project, same client id, same secret, same Internal consent screen, same Workspace.
Only one line is added (the master redirect URI above). Paste the existing client id/secret into master's `google` IdP.
Because a client can list several redirect URIs, the old realm keeps working during the switch.

## 7. Setup plan

1. **Google Cloud:** add the master redirect URI (section 5).
2. **Master realm:** create IdP `google` (existing id/secret, Hosted Domain `yserious.com`); add the two attribute mappers; declare
   the two user attributes. Confirm the redirector in master's browser flow stays off.
3. **Master client:** create `broker-for-yserious` (confidential), its redirect URI, its two protocol mappers; copy the secret.
4. **Create realm `yserious`;** declare `google_hd`, `google_sub`.
5. **Spoke IdP:** create `google-hub` (`keycloak-oidc`) with the master authorization URL above and the client id/secret.
   **Container gotcha (verified on the harness):** Keycloak runs in Docker and calls master's token/JWKS endpoints itself, and
   `localhost:8280` does not exist *inside* the container. The IdP's token and JWKS URLs are therefore
   `http://localhost:8080/realms/master/...` (inside the container Keycloak listens on 8080), the authorization URL stays on
   `8280` (the browser uses it), the IdP's `issuer` is left blank (the issuer master puts in a token depends on which URL
   was called), and `disableUserInfo` is on: a userinfo call with the internally-issued token failed with `invalid_token`,
   and everything needed is already in master's ID token.
6. **Spoke mappers:** the two attribute importers on `google-hub`.
7. **App client:** create `google-oidc-poc-frontend` in `yserious` with the audience mapper, the `idp_sub` mapper and the three
   constant claims.
8. **Point the apps:** frontend `keycloak.js` realm `yserious` and the IdP hint `google-hub`; backend issuer
   `http://localhost:8280/realms/yserious`.
9. **Test:** sign in; decode the JWT and confirm `iss`, `idp_sub` (the 21-digit Google subject), `tenant_id`; check the user exists
   in **both** realms; sign in with a personal Gmail and confirm it is refused.

Steps 2-7 are done by `scripts/setup-tenant.mjs` (idempotent; `--revert` removes a tenant). Step 1 (Google Cloud) and the
Google secret are yours. The chain and the gate minus Google are tested by `test-harness/scripts/hub-and-spoke-e2e.mjs`
(43 checks, passing: a local master user stands in for the Google sign-in; two tenants, cross-tenant refusals, each denial
reason, subject conflict, and a control that removes the gate and shows an unrelated account is then admitted). The real
Google sign-in through the chain has worked for `yserious.com`. **Not yet run with real Google:** Hosted Domain `*`, an
unrelated Workspace domain, and the personal-Gmail refusal through this chain.

## 8. What can be reused

- Google Cloud project, OAuth client, consent screen, Workspace, service account (unused for now).
- Docker stack, Keycloak image, databases, `run.md` flow, the frontend and backend code.
- The backend's token validators (signature, audience, tenant claims), tenant-scoped data and Postgres RLS, unchanged.
- `realm-config.mjs` helpers (user-profile attributes, client mappers).
- The old `google-oidc-poc` realm, left in place as a fallback.

## 9. What changes

| Item | Change |
|---|---|
| Realm | New `yserious` (and master gets a Google IdP). The Google IdP moves from the app realm to master |
| Tenant plugin / registry | **Not used** in the new realm: no SPI mapper, no registry file, no no-email-link flow. The `hd` check is master's Hosted Domain. (A tenant gate returns in a later step) |
| Hosted Domain | `yserious.com` at master for now (one tenant); becomes `*` plus a per-realm check when more tenants arrive |
| Claims | Produced by the chain plus constants, instead of by the SPI |
| Frontend | `keycloak.js` realm, IdP hint value |
| Backend | `app.tenant.issuer` -> `yserious`. The JWKS and validators follow |
| Master realm | Now also holds Google users (no admin roles). Treat the master realm as a service realm, not for people |

**Left out on purpose:** multiple tenants, Organizations, the tenant gate and registry, hardening flows, domain-wide
delegation, groups.
