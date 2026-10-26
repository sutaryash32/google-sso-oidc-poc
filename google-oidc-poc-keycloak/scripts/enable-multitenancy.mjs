// Turns the existing realm `google-oidc-poc` into the multi-tenant realm, in place and idempotently:
//   - Google IdP `google-oidc`: Hosted Domain  yserious.com  ->  *   (any Workspace org; consumer Gmail still rejected)
//   - tenant-resolver mapper on that IdP (the SPI): resolves hd -> tenant via tenant-registry.json, denies the rest
//   - user profile: tenant_id, tenant_domain, idp_alias, idp_subject editable and viewable by admins only
//   - client `google-oidc-poc-frontend` (client id unchanged): tenant_id, tenant_domain, idp, idp_sub and audience mappers
//     (idp / idp_sub are the PROVIDER's subject for the person: the stable key; Keycloak's own user id is not stable)
//   - back-fill of tenant and provider-identity attributes for existing Google-linked users
//
// With --harden (validated on the harness; apply to this realm when you are ready), additionally:
//   - first broker login flow that never links a new Google identity into an existing user by email
//   - token-time tenant guard on the client: no token, including a refresh, for a suspended tenant
//
// Realm name, client ids, the Google client id/secret and existing users are left as they are.
// The Hosted Domain is no longer the tenant boundary: the registry is (see ../tenant-registry.json).
//
// Usage:   node scripts/enable-multitenancy.mjs                     apply
//          node scripts/enable-multitenancy.mjs --harden            apply, plus the two hardening steps above
//          node scripts/enable-multitenancy.mjs --revert            restore Hosted Domain = yserious.com, remove the mappers
//                                                                   and the hardening, and use the built-in first-login flow again

import fs from 'node:fs';
import {
  applyNoEmailLinking, revertNoEmailLinking, backfillProviderIdentity, ensureClientMappers, ensureUserProfileAttributes,
  tenantClaimMappers, tenantGuardMapper, audienceMapper as makeAudienceMapper,
} from './lib/realm-config.mjs';

const KC = process.env.KC_URL ?? 'http://localhost:8280';
const REALM = 'google-oidc-poc';
const IDP = 'google-oidc';
const CLIENT = 'google-oidc-poc-frontend';
const AUDIENCE = process.env.TENANT_AUDIENCE ?? 'oidc-poc-api';
const REGISTRY_IN_CONTAINER = '/opt/keycloak/tenant-registry.json';
const ORIGINAL_HOSTED_DOMAIN = 'yserious.com';

async function adminToken() {
  const res = await fetch(`${KC}/realms/master/protocol/openid-connect/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'password', client_id: 'admin-cli', username: 'admin', password: 'admin' }),
  });
  if (!res.ok) throw new Error(`admin token failed: ${res.status} ${await res.text()}`);
  return (await res.json()).access_token;
}

let TOKEN;
async function api(method, path, body) {
  const res = await fetch(`${KC}/admin/realms/${REALM}${path}`, {
    method,
    headers: { authorization: `Bearer ${TOKEN}`, 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`${method} ${path} -> ${res.status} ${await res.text()}`);
  const text = await res.text();
  return text ? JSON.parse(text) : null;
}

const CLIENT_MAPPERS = [...tenantClaimMappers(), makeAudienceMapper(AUDIENCE)];

async function setIdpConfig(changes) {
  const idp = await api('GET', `/identity-provider/instances/${IDP}`);
  for (const [key, value] of Object.entries(changes)) {
    console.log(`  IdP ${IDP}: ${key} ${idp.config[key] ?? '(unset)'} -> ${value}`);
    idp.config[key] = value;
  }
  await api('PUT', `/identity-provider/instances/${IDP}`, idp); // the secret comes back masked and is kept as is
}

async function apply() {
  // prompt=select_account: users often hold several Google accounts; never silently reuse the wrong one.
  // (The admin console's Google form has no Prompt field, and saving that form can drop it, so it is set here.)
  await setIdpConfig({ hostedDomain: '*', prompt: 'select_account' });

  const mappers = await api('GET', `/identity-provider/instances/${IDP}/mappers`);
  if (mappers.some((m) => m.identityProviderMapper === 'tenant-resolver-mapper')) {
    console.log('  IdP mapper tenant-resolver: already present');
  } else {
    await api('POST', `/identity-provider/instances/${IDP}/mappers`, {
      name: 'tenant-resolver',
      identityProviderAlias: IDP,
      identityProviderMapper: 'tenant-resolver-mapper',
      config: { 'registry.file': REGISTRY_IN_CONTAINER, syncMode: 'FORCE' },
    });
    console.log('  IdP mapper tenant-resolver: created');
  }

  await ensureUserProfileAttributes(api);
  await ensureClientMappers(api, CLIENT, CLIENT_MAPPERS);

  await backfillExistingUsers();
  await backfillProviderIdentity(api, IDP);

  if (process.argv.includes('--harden')) {
    await applyNoEmailLinking(api, IDP);
    await ensureClientMappers(api, CLIENT, [tenantGuardMapper(REGISTRY_IN_CONTAINER)]);
  } else {
    console.log('  (hardening not applied: re-run with --harden for the no-email-linking flow and the token-time guard)');
  }
}

// Users created before this change have no tenant attributes, and the SPI only stamps them at the next
// Google sign-in. Back-fill them from the registry so a silent re-issue from an existing Keycloak session
// already carries the tenant. Only Google-linked users whose email domain belongs to exactly one active
// tenant are touched, and existing values are never overwritten.
async function backfillExistingUsers() {
  const registryPath = process.env.REGISTRY_FILE ?? new URL('../tenant-registry.json', import.meta.url);
  const registry = JSON.parse(fs.readFileSync(registryPath, 'utf8'));
  const users = await api('GET', '/users?max=1000');
  let stamped = 0;
  for (const u of users) {
    if (u.attributes?.tenant_id?.[0]) continue;
    const domain = (u.email ?? '').split('@')[1]?.toLowerCase();
    const owners = registry.tenants.filter((t) => t.status === 'active' && (t.domains ?? []).map((d) => d.toLowerCase()).includes(domain));
    if (!domain || owners.length !== 1) { console.log(`  back-fill: skipped ${u.email ?? u.username} (no single active tenant for its domain)`); continue; }
    const links = await api('GET', `/users/${u.id}/federated-identity`);
    if (!links.some((l) => l.identityProvider === IDP)) { console.log(`  back-fill: skipped ${u.email} (not linked to ${IDP})`); continue; }
    await api('PUT', `/users/${u.id}`, {
      ...u,
      attributes: { ...(u.attributes ?? {}), tenant_id: [owners[0].tenantId], tenant_domain: [domain] },
    });
    stamped++;
    console.log(`  back-fill: ${u.email} -> ${owners[0].tenantId}`);
  }
  console.log(`  back-fill: ${stamped} user(s) stamped`);
}

async function revert() {
  await setIdpConfig({ hostedDomain: ORIGINAL_HOSTED_DOMAIN });
  const mappers = await api('GET', `/identity-provider/instances/${IDP}/mappers`);
  for (const m of mappers.filter((x) => x.identityProviderMapper === 'tenant-resolver-mapper')) {
    await api('DELETE', `/identity-provider/instances/${IDP}/mappers/${m.id}`);
    console.log('  IdP mapper tenant-resolver: removed');
  }
  const client = (await api('GET', `/clients?clientId=${CLIENT}`))[0];
  await revertNoEmailLinking(api, IDP);
  const removable = [...CLIENT_MAPPERS, tenantGuardMapper(REGISTRY_IN_CONTAINER)];
  for (const m of (client.protocolMappers ?? []).filter((x) => removable.some((c) => c.name === x.name))) {
    await api('DELETE', `/clients/${client.id}/protocol-mappers/models/${m.id}`);
    console.log(`  client mapper ${m.name}: removed`);
  }
  console.log('  (user-profile tenant attributes left in place; they are harmless)');
}

TOKEN = await adminToken();
if (process.argv.includes('--revert')) {
  console.log(`Reverting multi-tenancy on realm ${REALM}`);
  await revert();
} else {
  console.log(`Enabling multi-tenancy on realm ${REALM}`);
  await apply();
}
console.log('done');
