# Google Workspace SSO over OIDC: Multi-Tenant Proof of Concept

## 1. Objective

Let each customer organization sign in to our application with its own **Google Workspace** accounts, using standard **OpenID Connect
(OIDC)**, with strong separation between customers.

- **Keycloak** is the identity broker. Each customer ("tenant") has its **own realm**, and therefore its own token issuer and keys.
- A **shared Google identity provider** lives once, in Keycloak's `master` realm. Customers reach it through their own realm.
- **Spring Boot** is the resource server. It validates tokens per issuer and serves each tenant only its own data.
- A **React** single-page app is the client.

This is the same hub-and-spoke pattern we already use for Microsoft Azure sign-in.

## 2. Authentication Flow

```
Google Workspace user
    -> Tenant realm (the customer's own realm; it will issue the token)
    -> google-hub identity provider (an OIDC client of the master realm)
    -> Master realm
    -> Shared Google identity provider
    -> Google Workspace
    ...and back: Google -> master -> tenant realm -> JWT issued by the tenant realm -> Spring Boot API
```

```mermaid
sequenceDiagram
    actor U as Workspace user
    participant A as React app
    participant T as Tenant realm (yserious)
    participant M as Master realm
    participant G as Google
    participant B as Spring Boot API
    U->>A: Open app
    A->>T: Authorization Code request (PKCE S256), hint google-hub
    T->>M: Broker request (client broker-for-yserious)
    M->>G: Redirect to Google sign-in
    G->>U: Authenticate and consent
    G->>M: Signed ID token (sub, email, email_verified, hd)
    M->>M: MASTER GATE: is this organization any tenant's?
    M->>T: Token with google_hd, google_sub, google_email_verified
    T->>T: TENANT GATE: does it belong to THIS tenant?
    T->>A: JWT issued by the tenant realm
    A->>B: API call with Bearer JWT
    B->>B: Validate issuer, signature, audience; tenant bound to issuer
    B->>A: Protected data
```

## 3. Keycloak Configuration

| Where | What |
|---|---|
| Master realm (once) | Shared Google identity provider (`google`): the one Google OAuth client, `prompt=select_account`, Hosted Domain `*`. Attribute importers for `hd`, `sub`, `email_verified`. The **master gate** |
| Master realm (per tenant) | A confidential broker client `broker-for-<tenant>` whose only redirect URI is that tenant realm's callback |
| Tenant realm (per tenant) | `google-hub` identity provider (an OIDC client of master), the **tenant gate**, the app client (Authorization Code flow with PKCE S256, audience `oidc-poc-api`) |
| Tokens | Signed by the tenant realm (RS256). They carry the tenant, the identity provider and the person's Google subject (`idp_sub`), the stable person key |

A new tenant is created with one script (`setup-tenant.mjs`), which is idempotent and has a read-only `--check`. No Keycloak console
work and **no change in Google Cloud** is needed per tenant.

## 4. Google Configuration

- **Organization:** the customer's Google Workspace (the first tenant is `yserious.com`).
- **OAuth client:** one, in Google Cloud, type *Web application*.
- **Authorized redirect URI:** exactly one, master's endpoint. Google never sees the tenant realms, so adding a tenant needs no Google change.
- **OAuth consent screen:** *External*, so organizations other than our own can reach the sign-in. It is currently in *Testing* mode, which
  admits only listed test accounts; publishing it admits any Google account, and the gates below still decide who gets in.
- **Personal Gmail accounts** carry no hosted-domain claim and are refused.

## 5. Security Controls

| Control | What it does |
|---|---|
| OIDC Authorization Code flow, PKCE (S256) | The browser never holds Google tokens; the app's code exchange is protected |
| **Master gate** | Before any user is created in master, the account's Google `hd`, verified email and email domain must belong to a tenant. A foreign organization is refused and **no record is created** |
| **Tenant gate** | Before any user is created in a tenant realm, the same checks run against **that tenant's** domains. A different tenant's account is refused, and a missing claim is always a denial |
| Realm per tenant | Each tenant has its own issuer, signing keys and users; suspending or removing one does not touch another |
| Issuer trust | The API trusts only the issuers registered for tenants; it never contacts an unregistered issuer |
| **Issuer-to-tenant binding** | A realm's tokens are accepted only for the tenant bound to that realm. A realm that writes another tenant's id into its tokens gets `403 issuer_mismatch` |
| JWT validation | Signature (that realm's keys), issuer, expiry and audience, on every request |
| Immediate suspension | The tenant registry is checked on every request: a removed tenant's still-valid token is rejected at once; a suspended one gets 403 |
| Tenant data isolation | Every query is scoped to the caller's tenant in the API and enforced again by Postgres row-level security |
| Stable person key | People are keyed on Google's `sub`, never on email or on Keycloak's internal id |

## 6. Validation Performed

With **real Google**:

- ✅ Google Workspace sign-in through the full chain (tenant realm → master → Google and back): both gates allowed it, and the API served the profile and Google Groups
- ✅ The token is issued by the tenant realm and carries the real Google subject, tenant and audience
- ✅ Personal Gmail account refused at master (no hosted-domain claim), with **no user created** in either realm

With a **mock Google**, in automated suites (they are repeatable and are run against a separate Keycloak):

- ✅ A second tenant signs in to its own realm only; each account is refused in the other tenant's realm
- ✅ Foreign organizations, consumer accounts, unverified emails and look-alike domains are refused at master, with nothing created
- ✅ A realm that forges another tenant's id is refused by the API, as is a realm nobody registered
- ✅ Removing or suspending a tenant takes effect on the next request; tenant data stays isolated
- ✅ Federated logout returns the browser to the app and ends the tenant session
- ✅ A control that removes a gate shows the refusals really are the gate's doing

**Not yet validated with real Google:** a managed account from a *foreign* Workspace organization (it needs a second Workspace; the
mock suites cover the logic).

## 7. Conclusion

The hub-and-spoke design is working end to end with a real Google Workspace identity: the user signs in through their own tenant realm,
Google's identity is brokered through one shared provider, and the API validates a token issued by the tenant's own realm. Two gates keep
tenants apart, and each tenant's issuer is bound to that tenant alone. The design is the same shape as our Azure SSO, so a new customer is
a script run and a registry entry, with no change in Google Cloud. Open items before production: the foreign-organization test with real
Google, domain-ownership verification for new tenants, roles and permissions (only tenant isolation exists today), and an API for creating tenants (today a script run).
