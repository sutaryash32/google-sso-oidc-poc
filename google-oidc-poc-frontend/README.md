# google-oidc-poc-frontend

React + Vite single-page app (port 5173). It signs the user in through their tenant's Keycloak realm and shows the resolved tenant,
the identity and the user's Google groups, all read from the backend (`localhost:8095`).

- **Login:** `keycloak-js` with the authorization-code flow and PKCE (S256), against realm **`yserious`** with the IdP hint
  **`google-hub`**: the tenant realm sends the browser through the `master` realm to Google and back (see the Keycloak README).
  The page shows `Tenant`, `Identity provider` (`google`) and the realm role from the token the realm issued.
- **Realm and hint are configurable** (`src/keycloak.js`): `VITE_KC_REALM` (default `yserious`) and `VITE_KC_IDP_HINT` (default
  `google-hub`). The earlier single-realm login is `VITE_KC_REALM=google-oidc-poc` with `VITE_KC_IDP_HINT=google-oidc`.
- **One realm per build:** the app is fixed to a single tenant realm. A login that chooses the tenant (by sign-in page, URL or email
  domain) is not built yet.
- **Sign out:** federated; the tenant realm's session and master's both end.

```powershell
npm install
npm run dev                                           # defaults: realm yserious, hint google-hub
$env:VITE_KC_REALM='google-oidc-poc'; $env:VITE_KC_IDP_HINT='google-oidc'; npm run dev     # the earlier single-realm login
```

Keycloak must be running (`http://localhost:8280`; starting the backend starts it). If the page shows 401 errors, the backend is
validating a different issuer than the token's: check the registry's `issuer` for the tenant.
