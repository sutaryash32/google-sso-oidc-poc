// Creates (or recreates) the spike-mt realm on the spike Keycloak:
//  - public client `spike-app` with tenant_id / tenant_domain protocol mappers
//  - OIDC identity provider `mock-google` pointing at the mock IdP
//  - tenant-resolver-mapper on that IdP (the SPI under test)
//  - declarative user profile with tenant_id / tenant_domain editable by admins only
//
// Usage: node scripts/setup-realm.mjs

import {
  applyNoEmailLinking, ensureUserProfileAttributes, tenantClaimMappers, tenantGuardMapper,
} from '../../scripts/lib/realm-config.mjs';

// The harness registry as seen from inside the harness Keycloak container.
const GUARD_REGISTRY = '/opt/keycloak/tenant-registry.json';

export const KC = process.env.KC_URL ?? 'http://localhost:8380';
export const REALM = 'spike-mt';

export async function adminToken() {
  const res = await fetch(`${KC}/realms/master/protocol/openid-connect/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'password', client_id: 'admin-cli', username: 'admin', password: 'admin',
    }),
  });
  if (!res.ok) throw new Error(`admin token failed: ${res.status} ${await res.text()}`);
  return (await res.json()).access_token;
}

async function api(token, method, path, body) {
  const res = await fetch(`${KC}/admin/realms${path}`, {
    method,
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!res.ok && res.status !== 404) {
    throw new Error(`${method} ${path} -> ${res.status} ${await res.text()}`);
  }
  return res;
}

const attrMapper = (name) => ({
  name,
  protocol: 'openid-connect',
  protocolMapper: 'oidc-usermodel-attribute-mapper',
  config: {
    'user.attribute': name,
    'claim.name': name,
    'jsonType.label': 'String',
    'id.token.claim': 'true',
    'access.token.claim': 'true',
    'userinfo.token.claim': 'true',
  },
});

// Audience the backend requires. Only clients that carry this mapper get tokens the API accepts.
const audienceMapper = {
  name: 'spike-api-audience',
  protocol: 'openid-connect',
  protocolMapper: 'oidc-audience-mapper',
  config: {
    'included.custom.audience': 'spike-api',
    'access.token.claim': 'true',
    'id.token.claim': 'false',
  },
};

const publicClient = (clientId, protocolMappers) => ({
  clientId,
  enabled: true,
  publicClient: true,
  standardFlowEnabled: true,
  directAccessGrantsEnabled: false,
  redirectUris: ['http://localhost:5174/*'],
  webOrigins: ['http://localhost:5174'],
  attributes: { 'pkce.code.challenge.method': 'S256' },
  protocolMappers,
});

async function main() {
  const token = await adminToken();

  await api(token, 'DELETE', `/${REALM}`);
  await api(token, 'POST', '', {
    realm: REALM, enabled: true, sslRequired: 'none', registrationAllowed: false,
  });

  // The app the backend is meant to serve: tenant + provider-identity claims, the API audience, and the token-time
  // tenant guard (refuses tokens, including refresh, for an inactive tenant).
  await api(token, 'POST', `/${REALM}/clients`,
    publicClient('spike-app', [...tenantClaimMappers(), audienceMapper, tenantGuardMapper(GUARD_REGISTRY)]));
  // Negative-test clients for the backend: a token with no tenant claims, and one with the wrong audience.
  await api(token, 'POST', `/${REALM}/clients`, publicClient('no-tenant-app', [audienceMapper]));
  await api(token, 'POST', `/${REALM}/clients`,
    publicClient('other-aud-app', [...tenantClaimMappers()]));

  await api(token, 'POST', `/${REALM}/identity-provider/instances`, {
    alias: 'mock-google',
    providerId: 'oidc',
    enabled: true,
    trustEmail: true,
    firstBrokerLoginFlowAlias: 'first broker login',
    config: {
      clientId: 'spike-kc',
      clientSecret: 'spike-secret',
      clientAuthMethod: 'client_secret_post',
      // Browser-facing URL uses localhost; server-to-server URLs reach the host from inside Docker.
      authorizationUrl: 'http://localhost:9100/authorize',
      tokenUrl: 'http://host.docker.internal:9100/token',
      jwksUrl: 'http://host.docker.internal:9100/jwks',
      useJwksUrl: 'true',
      validateSignature: 'true',
      issuer: 'http://localhost:9100',
      defaultScope: 'openid email profile',
      loginHint: 'true',
      disableUserInfo: 'true',
      syncMode: 'FORCE',
    },
  });

  await api(token, 'POST', `/${REALM}/identity-provider/instances/mock-google/mappers`, {
    name: 'tenant-resolver',
    identityProviderAlias: 'mock-google',
    identityProviderMapper: 'tenant-resolver-mapper',
    config: { 'registry.file': '/opt/keycloak/tenant-registry.json', syncMode: 'FORCE' },
  });

  // Declare the tenancy and provider-identity attributes so only admins can view/edit them (users cannot self-edit),
  // and never link a new Google identity into an existing user by email.
  const realmApi = async (method, path, body) => {
    const res = await api(token, method, `/${REALM}${path}`, body);
    const text = await res.text();
    return text ? JSON.parse(text) : null;
  };
  const quiet = () => {};
  await ensureUserProfileAttributes(realmApi, quiet);
  await applyNoEmailLinking(realmApi, 'mock-google', quiet);

  console.log(`realm ${REALM} ready at ${KC}/realms/${REALM}`);
}

if (import.meta.url === `file:///${process.argv[1].replace(/\\/g, '/')}`) {
  main().catch((e) => { console.error(e); process.exit(1); });
}
