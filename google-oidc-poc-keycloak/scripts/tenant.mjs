// Tenant provisioning for tenant-registry.json (read by the Keycloak SPI and by the backend, both
// reload on change, so no restart is needed).
//
//   node scripts/tenant.mjs list
//   node scripts/tenant.mjs add --id t-acme --name "Acme Corp" --domain acme.com [--domain acme.co.uk] [--groups-admin admin@acme.com] [--sso off] [--issuer http://localhost:8280/realms/acme]
//   node scripts/tenant.mjs set-issuer t-acme http://localhost:8280/realms/acme     (the tenant's own Keycloak realm; see setup-tenant.mjs)
//   node scripts/tenant.mjs add-domain t-acme acme.org
//   node scripts/tenant.mjs suspend t-acme [--no-revoke]   (also revokes the tenant's Keycloak sessions; see revokeTenantSessions)
//   node scripts/tenant.mjs activate t-acme
//
// Guards: a domain can belong to only one tenant (an ambiguous registry is denied at login), tenant ids are
// immutable, and a groups admin must belong to the tenant's own domains.
//
// NOT automated yet: proving that the customer owns the domain. Verify it (e.g. a DNS TXT challenge)
// BEFORE adding a tenant: the registry is what decides who may sign in.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FILE = process.env.REGISTRY_FILE ?? path.join(HERE, '..', 'tenant-registry.json');

const ID_RE = /^t-[a-z0-9][a-z0-9-]{1,40}$/;
const DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/;
const EMAIL_RE = /^[^@\s]+@([^@\s]+)$/;

const fail = (msg) => { console.error(`error: ${msg}`); process.exit(1); };
const normDomain = (d) => String(d).trim().toLowerCase().replace(/\.$/, '');

function load() {
  if (!fs.existsSync(FILE)) return { tenants: [] };
  const reg = JSON.parse(fs.readFileSync(FILE, 'utf8'));
  reg.tenants ??= [];
  return reg;
}

// Written in place (not via rename) so a bind-mounted single file keeps updating inside containers.
const save = (reg) => fs.writeFileSync(FILE, JSON.stringify(reg, null, 2) + '\n');

function domainOwner(reg, domain) {
  return reg.tenants.find((t) => t.domains.map(normDomain).includes(domain));
}

function parseFlags(args) {
  const flags = { domain: [] };
  const rest = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i].startsWith('--')) {
      const key = args[i].slice(2);
      const val = args[++i];
      if (val === undefined) fail(`--${key} needs a value`);
      if (key === 'domain') flags.domain.push(val); else flags[key] = val;
    } else rest.push(args[i]);
  }
  return { flags, rest };
}

// Public mail providers can never be a tenant (anyone can hold an address there), and a public suffix such as
// co.uk is not an organization's domain. The suffix check is a HEURISTIC for common country-code second levels;
// a production control plane must validate against the Public Suffix List instead.
const PUBLIC_MAIL = new Set(['gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'live.com', 'msn.com', 'yahoo.com',
  'ymail.com', 'icloud.com', 'me.com', 'aol.com', 'proton.me', 'protonmail.com', 'gmx.com', 'mail.com', 'zoho.com']);
const CC_SECOND_LEVEL = new Set(['co', 'com', 'org', 'net', 'gov', 'edu', 'ac', 'or', 'ne', 'go']);

function checkDomain(reg, raw, ownTenantId) {
  const d = normDomain(raw);
  if (!DOMAIN_RE.test(d)) fail(`"${raw}" is not a valid domain name`);
  if (PUBLIC_MAIL.has(d)) fail(`${d} is a public mail provider and cannot be a tenant domain`);
  const labels = d.split('.');
  if (labels.length === 2 && labels[1].length === 2 && CC_SECOND_LEVEL.has(labels[0])) {
    fail(`${d} looks like a public suffix, not an organization's domain (use e.g. acme.${d})`);
  }
  const owner = domainOwner(reg, d);
  if (owner && owner.tenantId !== ownTenantId) fail(`domain ${d} already belongs to tenant ${owner.tenantId}`);
  return d;
}

function checkAdmin(admin, domains) {
  const m = EMAIL_RE.exec(String(admin).trim().toLowerCase());
  if (!m) fail(`"${admin}" is not an email address`);
  if (!domains.includes(m[1])) fail(`groups admin ${admin} must belong to the tenant's own domains (${domains.join(', ')})`);
  return String(admin).trim().toLowerCase();
}

// Suspending in the registry only stops NEW sign-ins and backends that check the registry per request. Keycloak keeps
// honouring refresh tokens and SSO sessions it already issued (verified by test-harness/scripts/e2e-attacks.mjs), so
// the tenant's sessions must be revoked too. Needs Keycloak's admin API; if it is unreachable this says so loudly.
const KC_URL = process.env.KC_URL ?? 'http://localhost:8280';
const KC_REALM = process.env.KC_REALM ?? 'google-oidc-poc';
// The realm of an issuer URL such as http://localhost:8280/realms/acme; null if there is none.
const realmOf = (issuer) => (issuer ? /\/realms\/([^/]+)\/?$/.exec(String(issuer).trim())?.[1] ?? null : null);
const normIssuer = (u) => String(u).trim().replace(/\/+$/, '');
function checkIssuer(reg, raw, ownTenantId) {
  const u = normIssuer(raw);
  if (!/^https?:\/\/[^/\s]+\/realms\/[^/\s]+$/.test(u)) fail(`"${raw}" is not a Keycloak realm issuer URL (expected e.g. http://localhost:8280/realms/acme)`);
  const owner = reg.tenants.find((t) => t.issuer && normIssuer(t.issuer) === u);
  if (owner && owner.tenantId !== ownTenantId) fail(`issuer ${u} already belongs to tenant ${owner.tenantId}`);
  return u;
}

async function revokeTenantSessions(tenantId, tenant) {
  try {
    const tokenRes = await fetch(`${KC_URL}/realms/master/protocol/openid-connect/token`, {
      method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'password', client_id: 'admin-cli',
        username: process.env.KC_ADMIN_USER ?? 'admin', password: process.env.KC_ADMIN_PASSWORD ?? 'admin' }),
    });
    if (!tokenRes.ok) throw new Error(`admin login failed (HTTP ${tokenRes.status})`);
    const headers = { authorization: `Bearer ${(await tokenRes.json()).access_token}` };
    const realm = realmOf(tenant?.issuer);
    if (realm) {
      // Realm per tenant: the whole realm belongs to this tenant, so end every session in it. The people also have sessions
      // in master (the hub), found through the Google hosted domain it recorded on each of them.
      const out = await fetch(`${KC_URL}/admin/realms/${realm}/logout-all`, { method: 'POST', headers });
      if (!out.ok && out.status !== 204) throw new Error(`ending the sessions of realm ${realm} failed (HTTP ${out.status})`);
      let masterUsers = 0;
      for (const d of tenant.domains ?? []) {
        const res = await fetch(`${KC_URL}/admin/realms/master/users?q=${encodeURIComponent(`google_hd:${d}`)}&max=1000`, { headers });
        if (!res.ok) continue;
        for (const u of (await res.json()).filter((x) => (x.attributes?.google_hd ?? [])[0]?.toLowerCase() === d.toLowerCase())) {
          await fetch(`${KC_URL}/admin/realms/master/users/${u.id}/logout`, { method: 'POST', headers });
          masterUsers++;
        }
      }
      console.log(`ended every session in realm ${realm} and the master sessions of ${masterUsers} of its user(s) (refresh tokens and SSO sessions end now)`);
      return;
    }
    const res = await fetch(`${KC_URL}/admin/realms/${KC_REALM}/users?q=${encodeURIComponent(`tenant_id:${tenantId}`)}&max=1000`, { headers });
    if (!res.ok) throw new Error(`user search failed (HTTP ${res.status})`);
    const users = (await res.json()).filter((u) => (u.attributes?.tenant_id ?? [])[0] === tenantId);
    for (const u of users) await fetch(`${KC_URL}/admin/realms/${KC_REALM}/users/${u.id}/logout`, { method: 'POST', headers });
    console.log(`revoked the Keycloak sessions of ${users.length} user(s) in ${tenantId} (refresh tokens and SSO sessions end now)`);
  } catch (e) {
    console.error(`WARNING: could not revoke Keycloak sessions (${e.message}). The tenant is suspended in the registry, but users with an`);
    console.error('active Keycloak session or refresh token can still obtain tokens until they expire. Revoke the sessions in Keycloak.');
  }
}

const [cmd, ...args] = process.argv.slice(2);
const reg = load();

switch (cmd) {
  case 'list': {
    if (reg.tenants.length === 0) console.log('(no tenants)');
    for (const t of reg.tenants) {
      console.log(`${t.tenantId.padEnd(16)} ${t.status.padEnd(10)} sso=${t.ssoEnabled ? 'on ' : 'off'} ${t.domains.join(', ')}` +
        `${t.groupsDelegatedAdmin ? `  groups-admin=${t.groupsDelegatedAdmin}` : ''}${t.issuer ? `  issuer=${t.issuer}` : ''}  (${t.name})`);
    }
    break;
  }

  case 'add': {
    const { flags } = parseFlags(args);
    if (!flags.id || !flags.name || flags.domain.length === 0) fail('add needs --id, --name and at least one --domain');
    if (!ID_RE.test(flags.id)) fail(`tenant id must look like t-acme (lowercase letters, digits, dashes): "${flags.id}"`);
    if (reg.tenants.some((t) => t.tenantId === flags.id)) fail(`tenant ${flags.id} already exists`);
    const domains = [...new Set(flags.domain.map((d) => checkDomain(reg, d, flags.id)))];
    const tenant = { tenantId: flags.id, name: flags.name, status: 'active', ssoEnabled: (flags.sso ?? 'on') !== 'off', domains };
    if (flags['groups-admin']) tenant.groupsDelegatedAdmin = checkAdmin(flags['groups-admin'], domains);
    if (flags.issuer) tenant.issuer = checkIssuer(reg, flags.issuer, flags.id);
    reg.tenants.push(tenant);
    save(reg);
    console.log(`added ${tenant.tenantId} (${domains.join(', ')})`);
    console.log('reminder: confirm the customer owns these domains before they sign in. For accounts outside your own Workspace to');
    console.log('reach Keycloak at all, the Google OAuth consent screen must be External (Internal admits only your own organization).');
    break;
  }

  case 'add-domain': {
    const [id, domain] = args;
    const t = reg.tenants.find((x) => x.tenantId === id);
    if (!t) fail(`unknown tenant ${id}`);
    if (!domain) fail('usage: add-domain <tenantId> <domain>');
    const d = checkDomain(reg, domain, id);
    if (!t.domains.map(normDomain).includes(d)) t.domains.push(d);
    save(reg);
    console.log(`${id}: domains = ${t.domains.join(', ')}`);
    break;
  }

  case 'set-issuer': {
    const [id, issuer] = args;
    const t = reg.tenants.find((x) => x.tenantId === id);
    if (!t) fail(`unknown tenant ${id}`);
    if (!issuer) fail('usage: set-issuer <tenantId> <issuer URL>');
    t.issuer = checkIssuer(reg, issuer, id);
    save(reg);
    console.log(`${id}: issuer = ${t.issuer}`);
    console.log('the backend now trusts tokens from that realm for this tenant only, and for no other tenant.');
    break;
  }

  case 'suspend':
  case 'activate': {
    const [id] = args;
    const t = reg.tenants.find((x) => x.tenantId === id);
    if (!t) fail(`unknown tenant ${id}`);
    t.status = cmd === 'suspend' ? 'suspended' : 'active';
    save(reg);
    console.log(`${id}: ${t.status}`);
    if (cmd === 'suspend') {
      console.log('new logins are denied, and API requests return 403 immediately.');
      if (args.includes('--no-revoke')) console.log('skipped revoking Keycloak sessions (--no-revoke): refresh tokens and SSO sessions stay valid until they expire.');
      else await revokeTenantSessions(id, t);
    }
    break;
  }

  default:
    fail('usage: tenant.mjs list | add --id --name --domain [--groups-admin] [--sso off] [--issuer URL] | add-domain <id> <domain> | set-issuer <id> <URL> | suspend <id> | activate <id>');
}
