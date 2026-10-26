import Keycloak from 'keycloak-js';

// Default: the hub-and-spoke proof of concept (realm yserious, which brokers to Google through the master realm).
// For the older single realm that brokers to Google directly, start the dev server with
// VITE_KC_REALM=google-oidc-poc and VITE_KC_IDP_HINT=google-oidc (see run.md).
const keycloak = new Keycloak({
  url: 'http://localhost:8280',
  realm: import.meta.env.VITE_KC_REALM ?? 'yserious',
  clientId: 'google-oidc-poc-frontend',
});

export const idpHint = import.meta.env.VITE_KC_IDP_HINT ?? 'google-hub';

export default keycloak;
