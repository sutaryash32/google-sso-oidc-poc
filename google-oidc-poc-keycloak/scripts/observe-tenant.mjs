// Read-only snapshot for denial testing: who exists in master and in a tenant realm, and what the tenant gate and the
// Google IdP said recently. Run it before and after a sign-in attempt and compare.
//
//   node scripts/observe-tenant.mjs --id yserious [--lines 15]
//
// Env: KC_URL (default http://localhost:8280), KC_CONTAINER (default oidc-poc-keycloak).

import { execFileSync } from 'node:child_process';

const args = process.argv.slice(2);
const option = (name, fallback) => { const i = args.indexOf(`--${name}`); return i >= 0 ? args[i + 1] : fallback; };
const TENANT = option('id', 'yserious');
const LINES = Number(option('lines', '15'));
const KC = process.env.KC_URL ?? 'http://localhost:8280';
const CONTAINER = process.env.KC_CONTAINER ?? 'oidc-poc-keycloak';

const token = (await (await fetch(`${KC}/realms/master/protocol/openid-connect/token`, {
  method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({ grant_type: 'password', client_id: 'admin-cli', username: 'admin', password: 'admin' }),
})).json()).access_token;
const get = async (path) => {
  const res = await fetch(`${KC}/admin/realms${path}`, { headers: { authorization: `Bearer ${token}` } });
  return res.ok ? res.json() : null;
};

const when = (ms) => (ms ? new Date(ms).toISOString().replace('T', ' ').slice(0, 19) + 'Z' : '?');
async function users(realm, skipAdmin) {
  const list = (await get(`/${realm}/users?max=500`)) ?? [];
  const rows = [];
  for (const u of list.filter((x) => !(skipAdmin && x.username === 'admin') && !x.username.startsWith('service-account-'))) {
    const links = (await get(`/${realm}/users/${u.id}/federated-identity`)) ?? [];
    rows.push({ user: u.username, email: u.email ?? '', google_hd: u.attributes?.google_hd?.[0] ?? '',
      google_sub: u.attributes?.google_sub?.[0] ?? '', linked: links.map((l) => l.identityProvider).join(','), created: when(u.createdTimestamp) });
  }
  return rows;
}

const idp = await get('/master/identity-provider/instances/google');
console.log(`master Google IdP: ${idp ? `Hosted Domain "${idp.config.hostedDomain}"` : 'not found'}`);
const gate = (await get(`/${TENANT}/identity-provider/instances/google-hub/mappers`))?.find((m) => m.identityProviderMapper === 'hub-tenant-gate-mapper');
console.log(`realm ${TENANT} tenant gate: ${gate ? `bound domains ${gate.config['allowed.domains']}` : 'MISSING'}\n`);

const m = await users('master', true);
const t = await users(TENANT, false);
console.log(`master realm users (${m.length}):`); console.table(m);
console.log(`${TENANT} realm users (${t.length}):`); console.table(t);

let log = '';
try {
  log = execFileSync('docker', ['logs', CONTAINER, '--tail', '4000'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 64 * 1024 * 1024 });
} catch (e) { log = `${e.stdout ?? ''}${e.stderr ?? ''}`; }
const interesting = log.split('\n').filter((l) => /TENANT_(ALLOWED|DENIED)|IDENTITY_PROVIDER_LOGIN_ERROR|Hosted domain|hosted domain/i.test(l));
console.log(`last ${Math.min(LINES, interesting.length)} gate / login-error log lines:`);
for (const l of interesting.slice(-LINES)) console.log('  ' + l.replace(/\s+/g, ' ').slice(0, 230));
