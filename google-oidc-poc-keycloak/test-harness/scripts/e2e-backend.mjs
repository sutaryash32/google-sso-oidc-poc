// Backend enforcement checks, using REAL tokens from the spike Keycloak against the running
// google-oidc-poc-backend (profile "multitenant", port 8195) and the spike Postgres.
//
// Prereqs: spike Keycloak + mock IdP + spike-db up, realm set up (scripts/setup-realm.mjs),
//          backend running:  mvn spring-boot:run -Dspring-boot.run.profiles=multitenant
//                                                -Dspring-boot.run.jvmArguments=-Duser.timezone=UTC
// Usage:   node scripts/e2e-backend.mjs          (SKIP_EXPIRY=1 skips the ~65 s expiry check)

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { KC, REALM, adminToken } from './setup-realm.mjs';
import { tokenFor, decode } from './flow.mjs';

const BACKEND = process.env.BACKEND_URL ?? 'http://localhost:8195';
const HERE = path.dirname(fileURLToPath(import.meta.url));
const REGISTRY_FILE = path.join(HERE, '..', 'tenant-registry.json');

// ---------- helpers ----------
async function call(p, { token, method = 'GET', body, headers = {} } = {}) {
  const res = await fetch(`${BACKEND}${p}`, {
    method,
    headers: {
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
      ...headers,
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let json; try { json = JSON.parse(text); } catch { json = undefined; }
  return { status: res.status, json, text, www: res.headers.get('www-authenticate') };
}

const sql = (q) => execSync(`docker exec spike-db psql -U spike_owner -d spike -Atc "${q}"`, { encoding: 'utf8' }).trim();

const results = [];
function record(name, checks) {
  const failed = checks.filter((c) => !c.ok);
  results.push({ name, ok: failed.length === 0 });
  console.log(`${failed.length === 0 ? 'PASS' : 'FAIL'}  ${name}`);
  for (const c of failed) console.log(`        x ${c.what}${c.got !== undefined ? `  (got: ${c.got})` : ''}`);
}
const check = (what, ok, got) => ({ what, ok: !!ok, got });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function setAccessTokenLifespan(seconds) {
  const t = await adminToken();
  const res = await fetch(`${KC}/admin/realms/${REALM}`, {
    method: 'PUT', headers: { authorization: `Bearer ${t}`, 'content-type': 'application/json' },
    body: JSON.stringify({ accessTokenLifespan: seconds }),
  });
  if (!res.ok) throw new Error(`set lifespan failed: ${res.status}`);
}

async function main() {
  sql('truncate document_comment, document, app_user');
  console.log(`\nbackend enforcement e2e against ${BACKEND} (${new Date().toISOString()})\n`);

  const alice = await tokenFor({ persona: 'alice', hint: 'alice@acme.com' });
  const bob = await tokenFor({ persona: 'bob', hint: 'bob@globex.com' });
  const noTenant = await tokenFor({ persona: 'alice', clientId: 'no-tenant-app', hint: 'alice@acme.com' });
  const wrongAud = await tokenFor({ persona: 'alice', clientId: 'other-aud-app', hint: 'alice@acme.com' });

  record('TOKENS  real tokens carry what the backend relies on', [
    check('alice: tenant_id t-acme, audience spike-api',
      alice.claims.tenant_id === 't-acme' && [].concat(alice.claims.aud).includes('spike-api'), JSON.stringify([alice.claims.tenant_id, alice.claims.aud])),
    check('bob: tenant_id t-globex', bob.claims.tenant_id === 't-globex', bob.claims.tenant_id),
    check('alice: provider identity idp=mock-google idp_sub=g-alice (not the Keycloak sub)',
      alice.claims.idp === 'mock-google' && alice.claims.idp_sub === 'g-alice' && alice.claims.idp_sub !== alice.claims.sub,
      JSON.stringify([alice.claims.idp, alice.claims.idp_sub, alice.claims.sub])),
    check('no-tenant client token has no tenant_id', noTenant.claims.tenant_id === undefined, noTenant.claims.tenant_id),
    check('other-aud client token lacks audience spike-api', !([].concat(wrongAud.claims.aud ?? []).includes('spike-api')), JSON.stringify(wrongAud.claims.aud)),
  ]);

  // ---------- authentication / token validation ----------
  const pub = await call('/api/public');
  record('AUTH    public endpoint needs no token', [check('200', pub.status === 200, pub.status)]);

  const none = await call('/api/documents');
  record('AUTH    no token is rejected', [check('401', none.status === 401, none.status)]);

  const junk = await call('/api/documents', { token: 'not.a.jwt' });
  record('AUTH    garbage bearer is rejected', [check('401', junk.status === 401, junk.status)]);

  const tampered = alice.accessToken.slice(0, -4) + (alice.accessToken.endsWith('AAAA') ? 'BBBB' : 'AAAA');
  const t1 = await call('/api/documents', { token: tampered });
  record('AUTH    token with a tampered signature is rejected', [check('401', t1.status === 401, t1.status)]);

  const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid: 'attacker' })).toString('base64url');
  const body = Buffer.from(JSON.stringify(alice.claims)).toString('base64url'); // perfect claims, wrong key
  const forged = `${header}.${body}.${crypto.sign('RSA-SHA256', Buffer.from(`${header}.${body}`), privateKey).toString('base64url')}`;
  const t2 = await call('/api/documents', { token: forged });
  record('AUTH    token with valid claims signed by an unknown key is rejected', [check('401', t2.status === 401, t2.status)]);

  const t3 = await call('/api/documents', { token: noTenant.accessToken });
  record('AUTH    valid token with NO tenant_id is rejected (fail closed)', [
    check('401', t3.status === 401, t3.status), check('error is invalid_token', /invalid_token/.test(t3.www ?? ''), t3.www)]);

  const t4 = await call('/api/documents', { token: wrongAud.accessToken });
  record('AUTH    valid token for another audience is rejected', [check('401', t4.status === 401, t4.status)]);

  // ---------- tenant identity and isolation ----------
  const meA1 = await call('/api/tenant/me', { token: alice.accessToken });
  const meA2 = await call('/api/tenant/me', { token: alice.accessToken });
  const meB = await call('/api/tenant/me', { token: bob.accessToken });
  record('IDENTITY tenant context comes from the token; user keyed by (tenant, provider, provider subject)', [
    check('alice sees t-acme / acme.com', meA1.json?.tenantId === 't-acme' && meA1.json?.tenantDomain === 'acme.com', meA1.text),
    check('same user id on second call', meA1.json?.userId && meA1.json.userId === meA2.json?.userId),
    check('bob sees t-globex with a different user id', meB.json?.tenantId === 't-globex' && meB.json?.userId !== meA1.json?.userId, meB.text),
    check('exactly 2 app_user rows', sql('select count(*) from app_user') === '2', sql('select count(*) from app_user')),
    check('the row is keyed by the provider subject, not the Keycloak id',
      sql(`select idp_alias||'/'||idp_subject from app_user where email='alice@acme.com'`) === 'mock-google/g-alice',
      sql(`select idp_alias||'/'||idp_subject from app_user where email='alice@acme.com'`)),
  ]);

  // The Keycloak user id is not a stable person identifier: an admin clean-up that deletes the Keycloak user gives the
  // same person a NEW id on the next sign-in. The application identity must not change with it.
  const adm = await adminToken();
  const kcUser = (await (await fetch(`${KC}/admin/realms/${REALM}/users?email=alice@acme.com&exact=true`, { headers: { authorization: `Bearer ${adm}` } })).json())[0];
  await fetch(`${KC}/admin/realms/${REALM}/users/${kcUser.id}`, { method: 'DELETE', headers: { authorization: `Bearer ${adm}` } });
  const aliceRelinked = await tokenFor({ persona: 'alice', hint: 'alice@acme.com' });
  const meA3 = await call('/api/tenant/me', { token: aliceRelinked.accessToken });
  record('IDENTITY the person keeps the same application identity after the Keycloak user is deleted and re-created', [
    check('Keycloak assigned a NEW user id', aliceRelinked.claims.sub !== alice.claims.sub, `${alice.claims.sub} -> ${aliceRelinked.claims.sub}`),
    check('the provider subject is unchanged', aliceRelinked.claims.idp_sub === 'g-alice', aliceRelinked.claims.idp_sub),
    check('the backend resolves the SAME application user', meA3.json?.userId === meA1.json?.userId, `${meA1.json?.userId} vs ${meA3.json?.userId}`),
    check('no duplicate app_user row was created', sql(`select count(*) from app_user where email='alice@acme.com'`) === '1', sql(`select count(*) from app_user where email='alice@acme.com'`)),
  ]);

  const created = await call('/api/documents', { token: alice.accessToken, method: 'POST', body: { title: 'acme plan', body: 'secret' } });
  const bobCreated = await call('/api/documents', { token: bob.accessToken, method: 'POST', body: { title: 'globex plan', body: 'other' } });
  const listA = await call('/api/documents', { token: alice.accessToken });
  const listB = await call('/api/documents', { token: bob.accessToken });
  record('ISOLATE each tenant only lists its own documents', [
    check('alice created (201)', created.status === 201, created.status),
    check('bob created (201)', bobCreated.status === 201, bobCreated.status),
    check('alice lists exactly her document', listA.json?.length === 1 && listA.json[0].title === 'acme plan', listA.text),
    check('bob lists exactly his document', listB.json?.length === 1 && listB.json[0].title === 'globex plan', listB.text),
    check('rows stored with the right tenant_id', sql(`select string_agg(title||'='||tenant_id, ',' order by title) from document`) === 'acme plan=t-acme,globex plan=t-globex', sql(`select string_agg(title||'='||tenant_id, ',' order by title) from document`)),
  ]);

  const acmeDocId = created.json?.id;
  const bobGetsAcme = await call(`/api/documents/${acmeDocId}`, { token: bob.accessToken });
  const aliceGetsOwn = await call(`/api/documents/${acmeDocId}`, { token: alice.accessToken });
  record('ISOLATE another tenant\'s document id looks like it does not exist', [
    check('bob -> alice\'s doc is 404 (not 403)', bobGetsAcme.status === 404, bobGetsAcme.status),
    check('alice -> her doc is 200', aliceGetsOwn.status === 200, aliceGetsOwn.status),
  ]);

  const p1 = await call('/api/tenants/t-acme/documents', { token: bob.accessToken });
  const p2 = await call('/api/tenants/t-globex/documents', { token: bob.accessToken });
  const p3 = await call('/api/tenants/t-globex/documents', { token: alice.accessToken });
  const p4 = await call('/api/tenants/t-acme/documents', { token: alice.accessToken });
  record('PATH    tenant in the URL must equal the token\'s tenant, else 404', [
    check('bob -> /tenants/t-acme is 404', p1.status === 404, p1.status),
    check('bob -> /tenants/t-globex is 200', p2.status === 200 && p2.json?.length === 1, p2.status),
    check('alice -> /tenants/t-globex is 404', p3.status === 404, p3.status),
    check('alice -> /tenants/t-acme is 200', p4.status === 200 && p4.json?.length === 1, p4.status),
  ]);

  const spoofHeader = await call('/api/documents', { token: alice.accessToken, headers: { 'X-Tenant-Id': 't-globex', 'X-Tenant': 'globex.com' } });
  const spoofQuery = await call('/api/documents?tenantId=t-globex&tenant_id=t-globex', { token: alice.accessToken });
  const spoofBody = await call('/api/documents', { token: alice.accessToken, method: 'POST',
    body: { title: 'smuggle', body: 'x', tenantId: 't-globex', tenant_id: 't-globex' } });
  record('SPOOF   tenant supplied in header / query / body is ignored', [
    check('header spoof still returns only acme data', spoofHeader.json?.every((d) => d.title !== 'globex plan'), spoofHeader.text),
    check('query spoof still returns only acme data', spoofQuery.json?.every((d) => d.title !== 'globex plan'), spoofQuery.text),
    check('body spoof stored under the token\'s tenant', sql(`select tenant_id from document where title='smuggle'`) === 't-acme', sql(`select tenant_id from document where title='smuggle'`)),
    check('globex still has exactly 1 document', sql(`select count(*) from document where tenant_id='t-globex'`) === '1'),
  ]);

  // ---------- existing POC endpoints keep working, groups no longer trusts the URL ----------
  const poc = await call('/api/me', { token: alice.accessToken });
  const groupsOther = await call('/api/users/bob@globex.com/groups', { token: alice.accessToken });
  record('POC     existing /api/me works; groups endpoint refuses another user\'s email', [
    check('/api/me is 200', poc.status === 200, poc.status),
    check('groups for someone else is 403', groupsOther.status === 403, groupsOther.status),
  ]);

  // ---------- registry changes take effect on valid tokens ----------
  const original = fs.readFileSync(REGISTRY_FILE, 'utf8');
  try {
    const mod = JSON.parse(original);
    mod.tenants.find((t) => t.tenantId === 't-acme').status = 'suspended';
    fs.writeFileSync(REGISTRY_FILE, JSON.stringify(mod, null, 2));
    await sleep(1500);
    const sa = await call('/api/documents', { token: alice.accessToken });
    const sb = await call('/api/documents', { token: bob.accessToken });
    record('STATUS  suspending a tenant blocks its still-valid tokens immediately', [
      check('alice (t-acme) is 403 tenant_suspended', sa.status === 403 && sa.json?.error === 'tenant_suspended', sa.text),
      check('bob (t-globex) is unaffected', sb.status === 200, sb.status),
    ]);
  } finally {
    fs.writeFileSync(REGISTRY_FILE, original);
  }
  await sleep(1500);
  const back = await call('/api/documents', { token: alice.accessToken });
  record('STATUS  re-activating the tenant restores access', [check('alice is 200 again', back.status === 200, back.status)]);

  // ---------- expiry ----------
  if (!process.env.SKIP_EXPIRY) {
    await setAccessTokenLifespan(2);
    try {
      const short = await tokenFor({ persona: 'alice', hint: 'alice@acme.com' });
      const fresh = await call('/api/documents', { token: short.accessToken });
      console.log('      (waiting ~65 s: Spring\'s default 60 s clock skew applies to expiry)');
      await sleep(65_000);
      const expired = await call('/api/documents', { token: short.accessToken });
      record('EXPIRY  an expired token is rejected', [
        check('accepted while fresh', fresh.status === 200, fresh.status),
        check(`rejected after expiry (exp ${decode(short.accessToken).exp})`, expired.status === 401, expired.status)]);
    } finally {
      await setAccessTokenLifespan(300);
    }
  }

  const failed = results.filter((r) => !r.ok);
  console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
  process.exit(failed.length ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(2); });
