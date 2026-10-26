// READ-ONLY check of what enable-multitenancy.mjs sets up. Changes nothing, prints no secrets.
//
//   node scripts/check-multitenancy.mjs
//
// Env (defaults match the real stack): KC_URL=http://localhost:8280  KC_REALM=google-oidc-poc  KC_IDP=google-oidc
//   KC_CLIENT=google-oidc-poc-frontend  KC_ADMIN_USER / KC_ADMIN_PASSWORD (admin / admin)
// Exit code 1 if a required item is missing (the optional hardening only produces a note).

const KC = process.env.KC_URL ?? 'http://localhost:8280';
const REALM = process.env.KC_REALM ?? 'google-oidc-poc';
const IDP = process.env.KC_IDP ?? 'google-oidc';
const CLIENT = process.env.KC_CLIENT ?? 'google-oidc-poc-frontend';

const tokenRes = await fetch(`${KC}/realms/master/protocol/openid-connect/token`, {
  method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({ grant_type: 'password', client_id: 'admin-cli',
    username: process.env.KC_ADMIN_USER ?? 'admin', password: process.env.KC_ADMIN_PASSWORD ?? 'admin' }),
});
if (!tokenRes.ok) { console.error(`Cannot reach Keycloak at ${KC} (is the stack running? admin login HTTP ${tokenRes.status}).`); process.exit(2); }
const headers = { authorization: `Bearer ${(await tokenRes.json()).access_token}` };
const get = async (p) => { const r = await fetch(`${KC}/admin/realms/${REALM}${p}`, { headers }); return r.ok ? r.json() : null; };

let missing = 0;
const line = (ok, label, detail = '') => { if (!ok) missing++; console.log(`${ok ? '  OK    ' : '  MISSING'} ${label}${detail ? `  ${detail}` : ''}`); };
const note = (label, detail) => console.log(`  note    ${label}  ${detail}`);

console.log(`\nRealm "${REALM}" at ${KC}\n`);

const idp = await get(`/identity-provider/instances/${IDP}`);
console.log('1. Google login (Identity providers -> ' + IDP + ')');
line(!!idp, `identity provider "${IDP}" exists`);
if (idp) {
  line(idp.config.hostedDomain === '*', 'Hosted Domain is "*" (the tenant registry is the boundary now)', `(currently ${JSON.stringify(idp.config.hostedDomain)})`);
  line(idp.config.prompt === 'select_account', 'account chooser forced (prompt=select_account)', `(currently ${JSON.stringify(idp.config.prompt)})`);
  line(idp.config.syncMode === 'FORCE', 'sync mode FORCE', `(currently ${idp.config.syncMode})`);
  line(!!idp.config.clientId && !String(idp.config.clientId).startsWith('REPLACE'), 'Google client id is set (not the placeholder)');
  line(!!idp.config.clientSecret, 'Google client secret is set (value hidden)');
  const mappers = await get(`/identity-provider/instances/${IDP}/mappers`);
  const tenant = (mappers ?? []).find((m) => m.identityProviderMapper === 'tenant-resolver-mapper');
  line(!!tenant, 'tenant-resolver mapper (the tenant plugin) is attached', tenant ? `(registry file ${tenant.config['registry.file']})` : '');
  const hardened = idp.firstBrokerLoginFlowAlias === 'first broker login (no email linking)';
  note('first-login flow', `${idp.firstBrokerLoginFlowAlias}  ${hardened ? '(HARDENED: never links by email)' : '(default: can link by email; apply with --harden)'}`);
}

console.log('\n2. User attributes (Realm settings -> User profile)');
const profile = await get('/users/profile');
for (const name of ['tenant_id', 'tenant_domain', 'idp_alias', 'idp_subject']) {
  const a = profile?.attributes?.find((x) => x.name === name);
  line(!!a, `attribute ${name}`, a ? `(view: ${(a.permissions?.view ?? []).join(',')}; edit: ${(a.permissions?.edit ?? []).join(',')})` : '');
}

console.log(`\n3. Token claims (Clients -> ${CLIENT} -> Client scopes -> ${CLIENT}-dedicated)`);
const client = ((await get(`/clients?clientId=${encodeURIComponent(CLIENT)}`)) ?? [])[0];
line(!!client, `client "${CLIENT}" exists (id unchanged)`);
if (client) {
  const names = (client.protocolMappers ?? []).map((m) => m.name);
  for (const n of ['tenant_id', 'tenant_domain', 'idp', 'idp_sub']) line(names.includes(n), `claim mapper ${n}`);
  line(names.some((n) => n.endsWith('-audience')), 'audience mapper', `(${names.filter((n) => n.endsWith('-audience')).join(', ') || 'none'})`);
  note('token-time tenant guard', names.includes('tenant-guard') ? 'present (refuses tokens for a suspended tenant)' : 'not applied (apply with --harden)');
}

console.log('\n4. Users (Users -> a user -> Attributes tab)');
const users = (await get('/users?max=100')) ?? [];
if (users.length === 0) note('users', 'none yet: sign in once to create yours');
for (const u of users) {
  const a = u.attributes ?? {};
  const ok = a.tenant_id?.[0] && a.idp_subject?.[0];
  line(!!ok, u.email ?? u.username, `tenant=${a.tenant_id?.[0] ?? '-'}  provider=${a.idp_alias?.[0] ?? '-'}/${a.idp_subject?.[0] ?? '-'}`);
}

console.log(missing ? `\n${missing} required item(s) missing: run  node scripts\\enable-multitenancy.mjs\n` : '\nAll required items are in place.\n');
process.exit(missing ? 1 : 0);
