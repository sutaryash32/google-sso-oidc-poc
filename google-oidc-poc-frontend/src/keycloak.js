import Keycloak from 'keycloak-js';

// Each tenant has its own Keycloak realm (hub-and-spoke: the realm brokers to Google through the master realm). Which realm
// this browser signs in to is, in order:
//   1. VITE_KC_REALM, if set at build/dev-server start: fixed, no tenant choice (the earlier single-realm login is
//      VITE_KC_REALM=google-oidc-poc with VITE_KC_IDP_HINT=google-oidc);
//   2. ?tenant=<realm> in the URL (remembered), for deep links and testing;
//   3. the organization the user chose on the sign-in page (remembered in this browser);
//   4. the default tenant realm, yserious.
const DEFAULT_REALM = 'yserious';
const REALM_NAME = /^[a-z0-9][a-z0-9-]*$/;
const KEY = 'tenant';

export const tenantSelectable = !import.meta.env.VITE_KC_REALM;

function load() {
  try {
    const t = JSON.parse(localStorage.getItem(KEY) ?? 'null');
    return t && REALM_NAME.test(t.realm ?? '') ? t : null;
  } catch {
    return null;
  }
}

function save(tenant) {
  try {
    localStorage.setItem(KEY, JSON.stringify(tenant));
  } catch {
    /* storage unavailable: the choice just is not remembered */
  }
}

if (tenantSelectable) {
  const fromUrl = new URLSearchParams(window.location.search).get('tenant');
  if (fromUrl && REALM_NAME.test(fromUrl)) {
    save({ realm: fromUrl, domain: null });
    // Drop the parameter so the post-login redirect URI stays clean.
    window.history.replaceState({}, '', window.location.pathname + window.location.hash);
  }
}

const remembered = tenantSelectable ? load() : null;

/** The tenant this page signs in to: { realm, domain } (domain is null when unknown). */
export const tenant = {
  realm: import.meta.env.VITE_KC_REALM ?? remembered?.realm ?? DEFAULT_REALM,
  domain: remembered?.domain ?? null,
  chosen: remembered !== null,
};

const keycloak = new Keycloak({
  url: 'http://localhost:8280',
  realm: tenant.realm,
  clientId: 'google-oidc-poc-frontend',
});

export const idpHint = import.meta.env.VITE_KC_IDP_HINT ?? 'google-hub';

/** Switch to another tenant's realm: remember it, reload (the Keycloak client is bound to one realm) and sign in at once. */
export function switchTenant(realm, domain) {
  save({ realm, domain });
  try {
    sessionStorage.setItem('autoLogin', '1');
  } catch {
    /* the user just clicks Sign in again */
  }
  window.location.assign(window.location.pathname);
}

/** Forget the chosen tenant: back to the default realm. */
export function forgetTenant() {
  try {
    localStorage.removeItem(KEY);
  } catch {
    /* nothing to forget */
  }
  window.location.assign(window.location.pathname);
}

export default keycloak;
