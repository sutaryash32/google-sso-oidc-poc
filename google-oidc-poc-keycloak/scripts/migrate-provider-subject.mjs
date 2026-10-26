// One-off migration of an EXISTING application database to the provider-subject person key.
//
// Before: app_user(tenant_id, idp_subject, ...) where idp_subject actually held the KEYCLOAK user id (not stable).
// After:  app_user(tenant_id, idp_alias, idp_subject, ...) where both are the identity provider's values (for Google,
//         the "sub" claim), UNIQUE (tenant_id, idp_alias, idp_subject).
//
// Each existing row's Keycloak user id is translated through Keycloak's federated-identity link, whose userId IS the
// provider subject. Everything runs in ONE transaction, so it either migrates every row or changes nothing. A row whose
// Keycloak user no longer exists cannot be translated and stops the migration (decide what to do with it first).
//
// Usage:  node scripts/migrate-provider-subject.mjs [--dry-run]
// Env:    KC_URL (http://localhost:8280)  KC_REALM (google-oidc-poc)  KC_ADMIN_USER/KC_ADMIN_PASSWORD (admin/admin)
//         DB_CONTAINER (oidc-poc-app-db)  DB_NAME (app)  DB_OWNER (app_owner)

import { execFileSync } from 'node:child_process';

const KC = process.env.KC_URL ?? 'http://localhost:8280';
const REALM = process.env.KC_REALM ?? 'google-oidc-poc';
const CONTAINER = process.env.DB_CONTAINER ?? 'oidc-poc-app-db';
const DB = process.env.DB_NAME ?? 'app';
const OWNER = process.env.DB_OWNER ?? 'app_owner';
const DRY = process.argv.includes('--dry-run');

const psql = (sql) => execFileSync('docker', ['exec', '-i', CONTAINER, 'psql', '-U', OWNER, '-d', DB, '-v', 'ON_ERROR_STOP=1', '-Atq', '-c', sql],
  { encoding: 'utf8' }).trim();
const sqlText = (v) => `'${String(v).replace(/'/g, "''")}'`;

const hasColumn = psql(`select count(*) from information_schema.columns where table_name='app_user' and column_name='idp_alias'`) === '1';
if (hasColumn) {
  console.log('app_user already has idp_alias: nothing to migrate.');
  process.exit(0);
}

const rows = psql(`select user_id || '|' || tenant_id || '|' || idp_subject from app_user order by created_at`)
  .split('\n').filter(Boolean).map((l) => { const [userId, tenantId, keycloakSub] = l.split('|'); return { userId, tenantId, keycloakSub }; });
console.log(`${rows.length} app_user row(s) to translate`);

const tokenRes = await fetch(`${KC}/realms/master/protocol/openid-connect/token`, {
  method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({ grant_type: 'password', client_id: 'admin-cli',
    username: process.env.KC_ADMIN_USER ?? 'admin', password: process.env.KC_ADMIN_PASSWORD ?? 'admin' }),
});
if (!tokenRes.ok) { console.error(`cannot log in to Keycloak admin (HTTP ${tokenRes.status})`); process.exit(1); }
const headers = { authorization: `Bearer ${(await tokenRes.json()).access_token}` };

const statements = ['begin', 'alter table app_user add column idp_alias text'];
for (const r of rows) {
  const res = await fetch(`${KC}/admin/realms/${REALM}/users/${r.keycloakSub}/federated-identity`, { headers });
  if (!res.ok) { console.error(`row ${r.userId}: Keycloak user ${r.keycloakSub} not found (HTTP ${res.status}); migration stopped, nothing changed`); process.exit(1); }
  const link = (await res.json())[0];
  if (!link) { console.error(`row ${r.userId}: Keycloak user ${r.keycloakSub} has no federated identity; migration stopped, nothing changed`); process.exit(1); }
  console.log(`  ${r.userId}: keycloak ${r.keycloakSub} -> ${link.identityProvider}/${link.userId}`);
  statements.push(`update app_user set idp_alias = ${sqlText(link.identityProvider)}, idp_subject = ${sqlText(link.userId)} where user_id = ${sqlText(r.userId)}`);
}
statements.push(
  'alter table app_user alter column idp_alias set not null',
  'alter table app_user drop constraint if exists app_user_tenant_id_idp_subject_key',
  'alter table app_user add constraint app_user_person_key unique (tenant_id, idp_alias, idp_subject)',
  DRY ? 'rollback' : 'commit');

if (DRY) console.log('dry run: validating the whole migration, then rolling it back');
// One psql invocation so the transaction spans every statement.
execFileSync('docker', ['exec', '-i', CONTAINER, 'psql', '-U', OWNER, '-d', DB, '-v', 'ON_ERROR_STOP=1', '-q'],
  { input: statements.join(';\n') + ';\n', encoding: 'utf8' });
console.log(DRY ? 'dry run OK (rolled back)' : 'migrated');
