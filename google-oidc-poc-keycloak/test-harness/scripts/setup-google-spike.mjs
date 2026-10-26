// Creates the REAL-Google spike realm `spike-google` on the harness Keycloak (port 8380). It is isolated from the real
// realm (`google-oidc-poc`, port 8280): its own Keycloak, its own registry file, its own users.
//
// Unlike `spike-mt` (a mock Google), this realm talks to the real accounts.google.com. It has:
//   - IdP `google` (providerId google), Hosted Domain `*`, prompt=select_account
//   - the hardening under test: ID-token signature validation against Google's JWKS, issuer check, PKCE
//   - the tenant-resolver mapper with claim logging ON, so every login's real Google claims are recorded
//   - the first-login flow that never links by email, and the token-time tenant guard
//
// Credentials: Google OAuth client id and secret are read from the environment, or from test-harness/.env.google
// (KEY=VALUE lines, git-ignored). The secret is never printed.
//
// Before the first login, the Google OAuth client must list this redirect URI:
//     http://localhost:8380/realms/spike-google/broker/google/endpoint
//
// Usage:  node scripts/setup-google-spike.mjs
// Env:    GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET
//         GOOGLE_HOSTED_DOMAIN   default "*"; use "none" to leave Hosted Domain UNSET (the SPI is then the only hd check)
//         GOOGLE_HARDENING       default "on"; "off" disables signature validation, issuer check and PKCE (for comparison)
//         GOOGLE_JWKS_URL        override Google's JWKS URL (a bogus value proves signature validation is really active)

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { adminToken, KC } from './setup-realm.mjs';
import {
  applyNoEmailLinking, audienceMapper, ensureUserProfileAttributes, tenantClaimMappers, tenantGuardMapper,
} from '../../scripts/lib/realm-config.mjs';

export const GOOGLE_REALM = 'spike-google';
export const GOOGLE_IDP = 'google';
const REGISTRY_IN_CONTAINER = '/opt/keycloak/google-spike-registry.json';
const HERE = path.dirname(fileURLToPath(import.meta.url));

function loadCredentials() {
  const fromFile = {};
  const file = path.join(HERE, '..', '.env.google');
  if (fs.existsSync(file)) {
    for (const line of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
      const m = /^\s*([A-Z_]+)\s*=\s*(.*?)\s*$/.exec(line);
      if (m && !line.trim().startsWith('#')) fromFile[m[1]] = m[2].replace(/^["']|["']$/g, '');
    }
  }
  const clientId = process.env.GOOGLE_CLIENT_ID ?? fromFile.GOOGLE_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET ?? fromFile.GOOGLE_CLIENT_SECRET;
  if (!clientId || !clientSecret) {
    console.error('Google OAuth client credentials not found.\n' +
      'Create test-harness/.env.google (git-ignored) containing exactly:\n' +
      '  GOOGLE_CLIENT_ID=<your client id>\n  GOOGLE_CLIENT_SECRET=<your client secret>\n' +
      'or set those two environment variables, then run this script again.');
    process.exit(1);
  }
  return { clientId, clientSecret };
}

async function main() {
  const { clientId, clientSecret } = loadCredentials();
  const hosted = process.env.GOOGLE_HOSTED_DOMAIN ?? '*';
  const hardening = (process.env.GOOGLE_HARDENING ?? 'on') !== 'off';
  const token = await adminToken();
  const raw = async (method, p, body) => {
    const res = await fetch(`${KC}/admin/realms${p}`, {
      method, headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (!res.ok && res.status !== 404) throw new Error(`${method} ${p} -> ${res.status} ${await res.text()}`);
    return res;
  };
  const api = async (method, p, body) => {
    const res = await raw(method, `/${GOOGLE_REALM}${p}`, body);
    const text = await res.text();
    return text ? JSON.parse(text) : null;
  };

  await raw('DELETE', `/${GOOGLE_REALM}`);
  await raw('POST', '', { realm: GOOGLE_REALM, enabled: true, sslRequired: 'none', registrationAllowed: false });

  const config = {
    clientId, clientSecret,
    defaultScope: 'openid email profile',
    prompt: 'select_account',
    syncMode: 'FORCE',
  };
  if (hosted !== 'none') config.hostedDomain = hosted;
  if (hardening) {
    Object.assign(config, {
      validateSignature: 'true',
      useJwksUrl: 'true',
      jwksUrl: process.env.GOOGLE_JWKS_URL ?? 'https://www.googleapis.com/oauth2/v3/certs',
      issuer: 'https://accounts.google.com',
      pkceEnabled: 'true',
      pkceMethod: 'S256',
    });
  }
  await api('POST', '/identity-provider/instances', {
    alias: GOOGLE_IDP, providerId: 'google', enabled: true, trustEmail: true,
    firstBrokerLoginFlowAlias: 'first broker login', config,
  });

  await api('POST', `/identity-provider/instances/${GOOGLE_IDP}/mappers`, {
    name: 'tenant-resolver', identityProviderAlias: GOOGLE_IDP, identityProviderMapper: 'tenant-resolver-mapper',
    config: { 'registry.file': REGISTRY_IN_CONTAINER, 'log.claims': 'true', syncMode: 'FORCE' },
  });

  await api('POST', '/clients', {
    clientId: 'spike-app', enabled: true, publicClient: true, standardFlowEnabled: true, directAccessGrantsEnabled: false,
    redirectUris: ['http://localhost:5174/*'], webOrigins: ['http://localhost:5174'],
    attributes: { 'pkce.code.challenge.method': 'S256' },
    protocolMappers: [...tenantClaimMappers(), audienceMapper('spike-api'), tenantGuardMapper(REGISTRY_IN_CONTAINER)],
  });

  const quiet = () => {};
  await ensureUserProfileAttributes(api, quiet);
  await applyNoEmailLinking(api, GOOGLE_IDP, quiet);

  console.log(`realm ${GOOGLE_REALM} ready at ${KC}/realms/${GOOGLE_REALM}`);
  console.log(`  Google client id : ${clientId}`);
  console.log(`  Google secret    : set (${clientSecret.length} characters, not shown)`);
  console.log(`  Hosted Domain    : ${hosted === 'none' ? '(unset: the SPI is the only hd check)' : hosted}`);
  console.log(`  hardening        : ${hardening ? `ON (signature via ${config.jwksUrl}, issuer check, PKCE S256)` : 'OFF'}`);
  console.log('  registry         : test-harness/google-spike-registry.json  (t-yserious = yserious.com)');
  console.log('\nThe Google OAuth client must list this authorized redirect URI:');
  console.log(`  ${KC}/realms/${GOOGLE_REALM}/broker/${GOOGLE_IDP}/endpoint`);
  console.log('\nThen run:  node scripts/google-login.mjs      and open the URL it prints.');
}

if (import.meta.url === `file:///${process.argv[1].replace(/\\/g, '/')}`) {
  main().catch((e) => { console.error(e); process.exit(1); });
}
