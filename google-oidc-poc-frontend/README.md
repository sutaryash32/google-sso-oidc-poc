# google-oidc-poc-frontend

React + Vite single-page app (port 5173). It signs the user in through their tenant's Keycloak realm and shows the resolved tenant,
the identity and the user's Google groups, all read from the backend (`localhost:8095`).

- **Login:** `keycloak-js` with the authorization-code flow and PKCE (S256), against realm **`yserious`** with the IdP hint
  **`google-hub`**: the tenant realm sends the browser through the `master` realm to Google and back (see the Keycloak README).
  The page shows `Tenant`, `Identity provider` (`google`) and the realm role from the token the realm issued.
- **Realm and hint are configurable** (`src/keycloak.js`): `VITE_KC_REALM` (default `yserious`) and `VITE_KC_IDP_HINT` (default
  `google-hub`). The earlier single-realm login is `VITE_KC_REALM=google-oidc-poc` with `VITE_KC_IDP_HINT=google-oidc`.
- **Choosing the tenant, in one step:** the sign-in card asks for a **work email or organization domain** (`you@neelias.com` or
  `neelias.com`) and one **Continue** button. The page asks the backend (`GET /api/public/tenant?domain=`, unauthenticated, answers the
  realm name or the same 404 for anything that is not a serviceable tenant), remembers the realm in this browser, reloads against it and
  goes straight to Google. Next time the card shows one button, **Continue with Google**, for the remembered organization, with a
  "Not <organization>? Use a different organization" link. `?tenant=<realm>` in the URL does the same without the lookup. Setting
  `VITE_KC_REALM` fixes the realm: the card then just says the organization is fixed by configuration.
- **Sign out:** federated; the tenant realm's session and master's both end.

```powershell
npm install
npm run dev                                           # defaults: realm yserious, hint google-hub
$env:VITE_KC_REALM='google-oidc-poc'; $env:VITE_KC_IDP_HINT='google-oidc'; npm run dev     # the earlier single-realm login
```

Keycloak must be running (`http://localhost:8280`; starting the backend starts it). If the page shows 401 errors, the backend is
validating a different issuer than the token's: check the registry's `issuer` for the tenant.
