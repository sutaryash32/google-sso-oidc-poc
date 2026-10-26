// Hub-and-spoke setup (see docs/hub_and_spoke_poc_plan.md). Idempotent. One run sets up the shared hub (once) and one tenant.
//
//   realm master      IdP "google"  (the ONE shared Google IdP)  +  client "broker-for-<id>"  (one per tenant)
//   realm <id>        IdP "google-hub" (an OIDC client of master)  +  the TENANT GATE mapper  +  client "google-oidc-poc-frontend"
//
// Login: <id> -> google-hub -> master -> google -> Google Workspace, and back; the app JWT is issued by realm <id>.
// The tenant gate (hub-tenant-gate-mapper) runs in realm <id> before any user is created: the account's Google hd, its
// verified email and its email domain must belong to the domains bound to this realm with --domain. That, not master's
// Hosted Domain, is what keeps tenants apart.
//
// Usage:
//   node scripts/setup-tenant.mjs --id yserious --domain yserious.com
//   node scripts/setup-tenant.mjs --id acme --domain acme.com --domain acme.co.uk      (secondary domains: repeat --domain)
//   node scripts/setup-tenant.mjs --id yserious --domain yserious.com --hosted-domain '*'     (the later step: see below)
//   node scripts/setup-tenant.mjs --id acme --check             read-only: is the tenant wired up and its gate in place? (exit 1 if not)
//   node scripts/setup-tenant.mjs --id acme --revert            removes realm acme and its broker client (master is untouched)
//   node scripts/setup-tenant.mjs --id acme --revert --all      ... and master's shared Google IdP too
//
// Options:  --tenant-id t-acme   value of the tenant_id claim (default t-<id>)
//           --hosted-domain X    Hosted Domain of master's Google IdP. Applied only when given (or GOOGLE_HOSTED_DOMAIN is set);
//                                a new IdP otherwise starts restricted to the first --domain, and an existing one is left alone.
//                                '*' admits any Workspace at Google's door: only use it once the tenant gate is proven.
//
// Google secret: the Keycloak admin API masks it, so supply it when master's IdP does not exist yet (or to change it):
//   $env:GOOGLE_CLIENT_SECRET = '...'      (and GOOGLE_CLIENT_ID if different from the one in the old realm)
//
// Env (defaults suit the real stack):
//   KC_URL           browser-facing Keycloak URL                   http://localhost:8280
//   KC_INTERNAL_URL  how Keycloak itself reaches itself (server-to-server calls from a tenant realm to master)  http://localhost:8080
//   MASTER_HINT      kc_idp_hint master receives                   google  (only tests change this)

import crypto from 'node:crypto';
import {
  attributeMapper, audienceMapper, ensureClientMappers, ensureUserProfileAttributes,
} from './lib/realm-config.mjs';

const args = process.argv.slice(2);
const flag = (name) => args.includes(`--${name}`);
const option = (name) => { const i = args.indexOf(`--${name}`); return i >= 0 ? args[i + 1] : undefined; };
const options = (name) => args.flatMap((a, i) => (a === `--${name}` ? [args[i + 1]] : []));

const TENANT = option('id');
const DOMAINS = options('domain').map((d) => d.trim().toLowerCase()).filter(Boolean);
if (!TENANT || !/^[a-z0-9][a-z0-9-]*$/.test(TENANT) || TENANT === 'master') {
  throw new Error('usage: setup-tenant.mjs --id <realm name, lowercase, not "master"> --domain <domain> [--domain ...] [--revert [--all]]');
}
if (!flag('revert') && !flag('check') && DOMAINS.length === 0) throw new Error('at least one --domain is required (the domains bound to this tenant)');

const KC = process.env.KC_URL ?? 'http://localhost:8280';
const KC_INTERNAL = process.env.KC_INTERNAL_URL ?? 'http://localhost:8080';
const MASTER_HINT = process.env.MASTER_HINT ?? 'google';
const AUDIENCE = process.env.TENANT_AUDIENCE ?? 'oidc-poc-api';
const HOSTED_DOMAIN = option('hosted-domain') ?? process.env.GOOGLE_HOSTED_DOMAIN;   // undefined: do not change
const TENANT_ID = option('tenant-id') ?? `t-${TENANT}`;

const HUB_IDP = 'google-hub';
const MASTER_IDP = process.env.MASTER_IDP_ALIAS ?? 'google';     // only tests change this
const BROKER = `broker-for-${TENANT}`;
const APP = 'google-oidc-poc-frontend';
const OLD_REALM = 'google-oidc-poc';
const OLD_IDP = 'google-oidc';
// Google claims carried through both hops. google_email_verified exists only so the tenant gate can check it.
const CARRIED = [
  { attribute: 'google_hd', claim: 'hd' },
  { attribute: 'google_sub', claim: 'sub' },
  { attribute: 'google_email_verified', claim: 'email_verified' },
];
const CARRIED_ATTRIBUTES = CARRIED.map((c) => c.attribute);
const TENANT_CALLBACK = `${KC}/realms/${TENANT}/broker/${HUB_IDP}/endpoint`;
// Logging out of the tenant realm also logs out of master (federated logout); master only sends the browser back to a
// post-logout URI registered on the broker client.
const TENANT_LOGOUT_CALLBACK = `${TENANT_CALLBACK}/logout_response`;

let TOKEN;
async function adminToken() {
  const res = await fetch(`${KC}/realms/master/protocol/openid-connect/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'password', client_id: 'admin-cli', username: 'admin', password: 'admin' }),
  });
  if (!res.ok) throw new Error(`admin token failed: ${res.status} ${await res.text()}`);
  return (await res.json()).access_token;
}

/** api(method, path, body) bound to one realm; resolves to parsed JSON (null for an empty body), or throws. */
const apiFor = (realm) => async (method, path, body, { allow = [] } = {}) => {
  const res = await fetch(`${KC}/admin/realms${realm ? `/${realm}` : ''}${path}`, {
    method,
    headers: { authorization: `Bearer ${TOKEN}`, 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (allow.includes(res.status)) return null;
  if (!res.ok) throw new Error(`${method} ${realm ?? ''}${path} -> ${res.status} ${await res.text()}`);
  const text = await res.text();
  return text ? JSON.parse(text) : null;
};

const claimToAttributeMapper = (idpAlias, name, claim, attribute) => ({
  name, identityProviderAlias: idpAlias, identityProviderMapper: 'oidc-user-attribute-idp-mapper',
  config: { claim, 'user.attribute': attribute, syncMode: 'FORCE' },
});

const hardcodedClaim = (name, value) => ({
  name, protocol: 'openid-connect', protocolMapper: 'oidc-hardcoded-claim-mapper',
  config: { 'claim.name': name, 'claim.value': value, 'jsonType.label': 'String',
    'id.token.claim': 'true', 'access.token.claim': 'true', 'userinfo.token.claim': 'true' },
});

async function ensureIdpMappers(api, idpAlias, mappers) {
  const existing = new Set((await api('GET', `/identity-provider/instances/${idpAlias}/mappers`)).map((m) => m.name));
  const created = [];
  for (const m of mappers) {
    if (existing.has(m.name)) continue;
    await api('POST', `/identity-provider/instances/${idpAlias}/mappers`, m);
    created.push(m.name);
  }
  console.log(`  IdP ${idpAlias}: mappers ${created.length ? `created (${created.join(', ')})` : 'already present'}`);
}

// ---- master realm: the shared Google IdP (once) and the broker client for this tenant -------------------------------

async function setupMaster() {
  const master = apiFor('master');
  console.log('master realm');

  const secret = process.env.GOOGLE_CLIENT_SECRET;
  let clientId = process.env.GOOGLE_CLIENT_ID;
  if (!clientId) {
    // The id is not secret; reuse the one already configured in the old realm.
    const old = await apiFor(OLD_REALM)('GET', `/identity-provider/instances/${OLD_IDP}`, undefined, { allow: [404] });
    clientId = old?.config?.clientId;
  }

  const existing = await master('GET', `/identity-provider/instances/${MASTER_IDP}`, undefined, { allow: [404] });
  if (!existing) {
    if (!clientId || !secret) {
      throw new Error('master IdP "google" does not exist yet: set GOOGLE_CLIENT_SECRET (and GOOGLE_CLIENT_ID if the old '
        + `realm "${OLD_REALM}" has no IdP "${OLD_IDP}") and run again`);
    }
    const hosted = HOSTED_DOMAIN ?? DOMAINS[0];
    await master('POST', '/identity-provider/instances', {
      alias: MASTER_IDP, providerId: 'google', enabled: true, trustEmail: false, storeToken: false,
      firstBrokerLoginFlowAlias: 'first broker login',
      config: { clientId, clientSecret: secret, hostedDomain: hosted, prompt: 'select_account', syncMode: 'IMPORT' },
    });
    console.log(`  IdP ${MASTER_IDP}: created (Hosted Domain ${hosted}, client id ${clientId})`);
  } else {
    const before = existing.config.hostedDomain;
    if (HOSTED_DOMAIN) existing.config.hostedDomain = HOSTED_DOMAIN;
    existing.config.prompt = 'select_account';
    if (clientId && secret) existing.config.clientId = clientId;   // only with the secret: never pair a new id with the old secret
    if (secret) existing.config.clientSecret = secret;             // otherwise the masked value comes back and is kept as is
    await master('PUT', `/identity-provider/instances/${MASTER_IDP}`, existing);
    console.log(`  IdP ${MASTER_IDP}: already exists; Hosted Domain ${existing.config.hostedDomain}`
      + `${HOSTED_DOMAIN && HOSTED_DOMAIN !== before ? ` (was ${before})` : ' (unchanged)'}, ${secret ? 'secret updated' : 'secret unchanged'}`);
  }

  await ensureIdpMappers(master, MASTER_IDP, CARRIED.map((c) => claimToAttributeMapper(MASTER_IDP, c.attribute, c.claim, c.attribute)));
  await ensureUserProfileAttributes(master, console.log, CARRIED_ATTRIBUTES);

  // Broker client: what this tenant's google-hub IdP logs in as. Its only redirect URI is the tenant realm's callback.
  let client = (await master('GET', `/clients?clientId=${BROKER}`))[0];
  if (!client) {
    await master('POST', '/clients', {
      clientId: BROKER, protocol: 'openid-connect', enabled: true, publicClient: false, standardFlowEnabled: true,
      directAccessGrantsEnabled: false, serviceAccountsEnabled: false, fullScopeAllowed: false,
      secret: crypto.randomUUID(), redirectUris: [TENANT_CALLBACK], webOrigins: [],
      attributes: { 'post.logout.redirect.uris': TENANT_LOGOUT_CALLBACK },
    });
    client = (await master('GET', `/clients?clientId=${BROKER}`))[0];
    console.log(`  client ${BROKER}: created (redirect URI ${TENANT_CALLBACK})`);
  } else if (JSON.stringify(client.redirectUris) !== JSON.stringify([TENANT_CALLBACK])
      || client.attributes?.['post.logout.redirect.uris'] !== TENANT_LOGOUT_CALLBACK) {
    await master('PUT', `/clients/${client.id}`, {
      ...client, redirectUris: [TENANT_CALLBACK],
      attributes: { ...(client.attributes ?? {}), 'post.logout.redirect.uris': TENANT_LOGOUT_CALLBACK },
    });
    console.log(`  client ${BROKER}: redirect URI and post-logout redirect URI set`);
  } else {
    console.log(`  client ${BROKER}: already present`);
  }
  await ensureClientMappers(master, BROKER, CARRIED_ATTRIBUTES.map((a) => attributeMapper(a)));

  const { value } = await master('GET', `/clients/${client.id}/client-secret`);
  return value;
}

// ---- tenant realm: its google-hub IdP, the tenant gate and the app client -------------------------------------------

async function ensureGate(api) {
  const config = { 'allowed.domains': DOMAINS.join(','), syncMode: 'FORCE' };
  const mappers = await api('GET', `/identity-provider/instances/${HUB_IDP}/mappers`);
  const gate = mappers.find((m) => m.identityProviderMapper === 'hub-tenant-gate-mapper');
  if (!gate) {
    await api('POST', `/identity-provider/instances/${HUB_IDP}/mappers`, {
      name: 'tenant-gate', identityProviderAlias: HUB_IDP, identityProviderMapper: 'hub-tenant-gate-mapper', config,
    });
    console.log(`  IdP ${HUB_IDP}: tenant gate created (bound domains: ${DOMAINS.join(', ')})`);
  } else if (gate.config?.['allowed.domains'] !== config['allowed.domains']) {
    await api('PUT', `/identity-provider/instances/${HUB_IDP}/mappers/${gate.id}`, { ...gate, config });
    console.log(`  IdP ${HUB_IDP}: tenant gate updated (bound domains: ${gate.config?.['allowed.domains']} -> ${DOMAINS.join(', ')})`);
  } else {
    console.log(`  IdP ${HUB_IDP}: tenant gate already present (bound domains: ${DOMAINS.join(', ')})`);
  }
}

/** The domains bound across ALL tenant realms: every realm with a google-hub IdP and a tenant gate. */
async function allTenantDomains() {
  const domains = new Set();
  for (const r of (await apiFor(null)('GET', '')) ?? []) {
    if (r.realm === 'master') continue;
    const api = apiFor(r.realm);
    const gate = (await api('GET', `/identity-provider/instances/${HUB_IDP}/mappers`, undefined, { allow: [404] }))
      ?.find((m) => m.identityProviderMapper === 'hub-tenant-gate-mapper');
    for (const d of (gate?.config?.['allowed.domains'] ?? '').split(/[,\s]+/).filter(Boolean)) domains.add(d.toLowerCase());
  }
  return [...domains].sort();
}

/**
 * The same gate on master's own Google IdP, bound to the union of every tenant's domains and reading Google's raw claims.
 * An organisation that is nobody's tenant is then refused at master, and no user is created there for it. Recomputed from the
 * realms themselves, so adding or removing a tenant never leaves it stale. An empty union denies every login.
 */
async function syncMasterGate() {
  const master = apiFor('master');
  if (!(await master('GET', `/identity-provider/instances/${MASTER_IDP}`, undefined, { allow: [404] }))) return;
  const domains = await allTenantDomains();
  const config = { 'allowed.domains': domains.join(','), 'claim.prefix': 'raw', 'gate.name': 'master', syncMode: 'FORCE' };
  const mappers = await master('GET', `/identity-provider/instances/${MASTER_IDP}/mappers`);
  const gate = mappers.find((m) => m.identityProviderMapper === 'hub-tenant-gate-mapper');
  if (!gate) {
    await master('POST', `/identity-provider/instances/${MASTER_IDP}/mappers`, {
      name: 'master-tenant-gate', identityProviderAlias: MASTER_IDP, identityProviderMapper: 'hub-tenant-gate-mapper', config,
    });
    console.log(`  master IdP ${MASTER_IDP}: master gate created (all tenants' domains: ${domains.join(', ') || 'none'})`);
  } else if (gate.config?.['allowed.domains'] !== config['allowed.domains'] || gate.config?.['claim.prefix'] !== 'raw') {
    await master('PUT', `/identity-provider/instances/${MASTER_IDP}/mappers/${gate.id}`, { ...gate, config });
    console.log(`  master IdP ${MASTER_IDP}: master gate updated (${gate.config?.['allowed.domains'] || 'none'} -> ${domains.join(', ') || 'none'})`);
  } else {
    console.log(`  master IdP ${MASTER_IDP}: master gate already present (all tenants' domains: ${domains.join(', ')})`);
  }
}

async function setupTenant(brokerSecret) {
  console.log(`${TENANT} realm (tenant ${TENANT_ID}, domains ${DOMAINS.join(', ')})`);
  const realms = apiFor(null);
  if (await realms('GET', `/${TENANT}`, undefined, { allow: [404] })) {
    console.log('  realm: already exists');
  } else {
    await realms('POST', '', { realm: TENANT, displayName: TENANT, enabled: true });
    console.log('  realm: created');
  }
  const api = apiFor(TENANT);
  await ensureUserProfileAttributes(api, console.log, CARRIED_ATTRIBUTES);

  // The browser goes to KC (8280). Keycloak's own server-to-server calls to master use KC_INTERNAL, because the
  // container cannot reach the published port. `issuer` is left blank: the issuer master stamps into a token depends on
  // which URL was called, so a fixed value would not match.
  const master = `/realms/master/protocol/openid-connect`;
  const hub = {
    alias: HUB_IDP, displayName: 'Google (via master)', providerId: 'keycloak-oidc', enabled: true,
    trustEmail: false, storeToken: false, firstBrokerLoginFlowAlias: 'first broker login',
    config: {
      authorizationUrl: `${KC}${master}/auth?kc_idp_hint=${MASTER_HINT}`,
      tokenUrl: `${KC_INTERNAL}${master}/token`,
      userInfoUrl: `${KC_INTERNAL}${master}/userinfo`,
      jwksUrl: `${KC_INTERNAL}${master}/certs`,
      logoutUrl: `${KC}${master}/logout`,
      clientId: BROKER, clientSecret: brokerSecret, clientAuthMethod: 'client_secret_post',
      validateSignature: 'true', useJwksUrl: 'true', issuer: '', defaultScope: 'openid', syncMode: 'IMPORT',
      // Everything needed is in master's ID token (the broker client's mappers add it). A userinfo call would need the
      // access token to validate against the internal URL's issuer, and adds nothing.
      disableUserInfo: 'true',
    },
  };
  const existing = await api('GET', `/identity-provider/instances/${HUB_IDP}`, undefined, { allow: [404] });
  if (!existing) {
    await api('POST', '/identity-provider/instances', hub);
    console.log(`  IdP ${HUB_IDP}: created`);
  } else {
    await api('PUT', `/identity-provider/instances/${HUB_IDP}`, { ...existing, ...hub });
    console.log(`  IdP ${HUB_IDP}: updated`);
  }
  await ensureIdpMappers(api, HUB_IDP, CARRIED.map((c) => claimToAttributeMapper(HUB_IDP, c.attribute, c.attribute, c.attribute)));
  await ensureGate(api);

  // App client: same id as in the old realm. Redirect URIs and attributes are copied from it when it exists.
  const old = (await apiFor(OLD_REALM)('GET', `/clients?clientId=${APP}`, undefined, { allow: [404] }))?.[0];
  let app = (await api('GET', `/clients?clientId=${APP}`))[0];
  if (!app) {
    await api('POST', '/clients', {
      clientId: APP, protocol: 'openid-connect', enabled: true, publicClient: true, standardFlowEnabled: true,
      directAccessGrantsEnabled: false,
      redirectUris: old?.redirectUris ?? ['http://localhost:5173/*'],
      webOrigins: old?.webOrigins ?? ['http://localhost:5173'],
      attributes: { 'pkce.code.challenge.method': 'S256',
        'post.logout.redirect.uris': old?.attributes?.['post.logout.redirect.uris'] ?? '+' },
    });
    app = (await api('GET', `/clients?clientId=${APP}`))[0];
    console.log(`  client ${APP}: created`);
  } else {
    console.log(`  client ${APP}: already present`);
  }
  // tenant_id / tenant_domain / idp are constants of this realm; idp_sub is the person's Google subject. (Here the tenant
  // IS the realm, so a backend that validates per issuer can derive the tenant from `iss` and ignore these.)
  await ensureClientMappers(api, APP, [
    attributeMapper('idp_sub', 'google_sub', 'idp_sub'),
    hardcodedClaim('tenant_id', TENANT_ID),
    hardcodedClaim('tenant_domain', DOMAINS[0]),
    hardcodedClaim('idp', 'google'),
    audienceMapper(AUDIENCE),
  ]);
}

async function revert() {
  console.log(`Reverting tenant ${TENANT}`);
  await apiFor(null)('DELETE', `/${TENANT}`, undefined, { allow: [404] });
  console.log(`  realm ${TENANT}: deleted (if it existed)`);
  const master = apiFor('master');
  const client = (await master('GET', `/clients?clientId=${BROKER}`))[0];
  if (client) { await master('DELETE', `/clients/${client.id}`); console.log(`  client ${BROKER}: deleted`); }
  if (flag('all')) {
    await master('DELETE', `/identity-provider/instances/${MASTER_IDP}`, undefined, { allow: [404] });
    console.log(`  master IdP ${MASTER_IDP}: deleted (if it existed)`);
  }
  if (!flag('all')) await syncMasterGate();
  console.log('  (the old realm is untouched; the Google Cloud redirect URI is left in place)');
}

/**
 * Read-only: is this tenant wired up, and is its gate in place? A realm whose gate mapper is missing admits whatever
 * master admits, so this is the check to run after any change to the realm. Exits 1 if anything is missing.
 */
async function check() {
  console.log(`Checking tenant ${TENANT}`);
  const problems = [];
  const report = (ok, text) => { console.log(`  ${ok ? 'OK     ' : 'MISSING'} ${text}`); if (!ok) problems.push(text); };
  const realm = await apiFor(null)('GET', `/${TENANT}`, undefined, { allow: [404] });
  report(!!realm, `realm ${TENANT}`);
  if (realm) {
    const api = apiFor(TENANT);
    const idp = await api('GET', `/identity-provider/instances/${HUB_IDP}`, undefined, { allow: [404] });
    report(!!idp?.enabled, `IdP ${HUB_IDP} (enabled)`);
    const mappers = idp ? await api('GET', `/identity-provider/instances/${HUB_IDP}/mappers`) : [];
    const gate = mappers.find((m) => m.identityProviderMapper === 'hub-tenant-gate-mapper');
    const bound = gate?.config?.['allowed.domains'] ?? '';
    report(!!gate && bound.trim() !== '', `tenant gate with bound domains${bound ? ` (${bound})` : ''}`);
    if (gate && DOMAINS.length) report(bound === DOMAINS.join(','), `bound domains equal ${DOMAINS.join(',')}`);
    for (const c of CARRIED) report(mappers.some((m) => m.name === c.attribute), `IdP mapper ${c.attribute}`);
  }
  const master = apiFor('master');
  const mIdp = await master('GET', `/identity-provider/instances/${MASTER_IDP}`, undefined, { allow: [404] });
  report(!!mIdp, `master IdP ${MASTER_IDP}${mIdp ? ` (Hosted Domain ${mIdp.config.hostedDomain})` : ''}`);
  const mGate = mIdp ? (await master('GET', `/identity-provider/instances/${MASTER_IDP}/mappers`))
    .find((m) => m.identityProviderMapper === 'hub-tenant-gate-mapper') : null;
  const masterDomains = (mGate?.config?.['allowed.domains'] ?? '').split(/[,\s]+/).filter(Boolean);
  report(!!mGate && masterDomains.length > 0, `master gate with all tenants' domains${masterDomains.length ? ` (${masterDomains.join(', ')})` : ''}`);
  const own = DOMAINS.length ? DOMAINS : ((await apiFor(TENANT)('GET', `/identity-provider/instances/${HUB_IDP}/mappers`, undefined, { allow: [404] }))
    ?.find((m) => m.identityProviderMapper === 'hub-tenant-gate-mapper')?.config?.['allowed.domains'] ?? '').split(/[,\s]+/).filter(Boolean);
  report(own.length > 0 && own.every((d) => masterDomains.includes(d.toLowerCase())), `master gate includes this tenant's domains (${own.join(', ')})`);
  const client = (await master('GET', `/clients?clientId=${BROKER}`))[0];
  report(!!client && JSON.stringify(client.redirectUris) === JSON.stringify([TENANT_CALLBACK]), `client ${BROKER} with redirect URI ${TENANT_CALLBACK}`);
  console.log(problems.length ? `\n${problems.length} problem(s)` : '\nall present');
  process.exitCode = problems.length ? 1 : 0;
}

TOKEN = await adminToken();
if (flag('check')) {
  await check();
} else if (flag('revert')) {
  await revert();
} else {
  console.log(`Setting up tenant ${TENANT}`);
  await setupTenant(await setupMaster());
  console.log('master realm');
  await syncMasterGate();
  const hosted = (await apiFor('master')('GET', `/identity-provider/instances/${MASTER_IDP}`)).config.hostedDomain;
  console.log(`\nGoogle Cloud (OAuth client -> Authorized redirect URIs) must contain:\n  ${KC}/realms/master/broker/${MASTER_IDP}/endpoint`);
  console.log(`Master's Google IdP Hosted Domain is "${hosted}".`);
  if (hosted !== '*' && !DOMAINS.includes(hosted)) {
    console.log(`  Accounts from ${DOMAINS.join(', ')} are stopped at Google's door until that is set to '*' (--hosted-domain '*').`
      + '\n  Do that only after the tenant gate has been proven for this realm.');
  } else if (hosted === '*') {
    console.log('  Any Workspace can reach master; the tenant gate in each realm is what keeps tenants apart.');
  }
}
console.log('done');
