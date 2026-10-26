// End-to-end scenarios against the spike Keycloak + mock IdP.
// Drives the real browser flow (authorization code + PKCE) hop by hop with a cookie jar,
// then checks: issued claims, whether a Keycloak user was created, and the SPI's logged reason.
//
// Prereqs: spike Keycloak up, mock IdP running, `node scripts/setup-realm.mjs` done.
// Usage:   node scripts/e2e.mjs

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { KC, REALM, adminToken } from './setup-realm.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REGISTRY_FILE = path.join(HERE, '..', 'tenant-registry.json');
const REDIRECT = 'http://localhost:5174/cb';

// ---------- tiny cookie jar (keyed by origin) ----------
class Jar {
  #c = new Map();
  store(url, res) {
    const origin = new URL(url).origin;
    for (const sc of res.headers.getSetCookie()) {
      const [pair] = sc.split(';');
      const i = pair.indexOf('=');
      const name = pair.slice(0, i).trim();
      const value = pair.slice(i + 1);
      const key = `${origin}|${name}`;
      if (/max-age=0|expires=thu, 01 jan 1970/i.test(sc) || value === '') this.#c.delete(key);
      else this.#c.set(key, value);
    }
  }
  header(url) {
    const origin = new URL(url).origin;
    return [...this.#c].filter(([k]) => k.startsWith(origin + '|'))
      .map(([k, v]) => `${k.split('|')[1]}=${v}`).join('; ');
  }
}

// ---------- browser flow ----------
async function login({ persona, hint }) {
  const jar = new Jar();
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  const params = new URLSearchParams({
    client_id: 'spike-app', redirect_uri: REDIRECT, response_type: 'code', scope: 'openid',
    state: crypto.randomUUID(), nonce: crypto.randomUUID(),
    code_challenge: challenge, code_challenge_method: 'S256', kc_idp_hint: 'mock-google',
  });
  if (hint) params.set('login_hint', hint);

  let url = `${KC}/realms/${REALM}/protocol/openid-connect/auth?${params}`;
  for (let hop = 0; hop < 20; hop++) {
    const headers = { cookie: jar.header(url) };
    if (new URL(url).port === '9100') headers['x-persona'] = persona;
    const res = await fetch(url, { redirect: 'manual', headers });
    jar.store(url, res);
    if (res.status >= 300 && res.status < 400) {
      const next = new URL(res.headers.get('location'), url).toString();
      if (next.startsWith(REDIRECT)) {
        const q = new URL(next).searchParams;
        if (q.get('error')) return { outcome: 'error', error: q.get('error'), description: q.get('error_description') };
        return { outcome: 'code', code: q.get('code'), verifier };
      }
      url = next;
      continue;
    }
    const body = await res.text();
    return { outcome: 'page', status: res.status, text: body.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 240) };
  }
  return { outcome: 'page', status: 0, text: 'too many redirects' };
}

async function redeem({ code, verifier }) {
  const res = await fetch(`${KC}/realms/${REALM}/protocol/openid-connect/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code', client_id: 'spike-app', code,
      redirect_uri: REDIRECT, code_verifier: verifier,
    }),
  });
  const json = await res.json();
  if (!res.ok) throw new Error(`token redeem failed: ${JSON.stringify(json)}`);
  const payload = (jwt) => JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString());
  return { access: payload(json.access_token), id: payload(json.id_token), raw: json };
}

// ---------- admin helpers ----------
let TOKEN;
const admin = async (method, p, body) => {
  const res = await fetch(`${KC}/admin/realms/${REALM}${p}`, {
    method, headers: { authorization: `Bearer ${TOKEN}`, 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`${method} ${p} -> ${res.status} ${await res.text()}`);
  return res.status === 204 || res.status === 201 ? null : res.json();
};
const users = () => admin('GET', '/users?max=200');
const userByEmail = async (email) =>
  (await admin('GET', `/users?email=${encodeURIComponent(email)}&exact=true`))[0];
const wipeUsers = async () => { for (const u of await users()) await admin('DELETE', `/users/${u.id}`); };

const logsSince = (sinceIso) =>
  execSync(`docker logs spike-keycloak --since ${sinceIso} 2>&1`, { encoding: 'utf8', maxBuffer: 20e6 });

// ---------- assertions / reporting ----------
const results = [];
function record(name, checks) {
  const failed = checks.filter((c) => !c.ok);
  results.push({ name, ok: failed.length === 0, failed, checks });
  console.log(`${failed.length === 0 ? 'PASS' : 'FAIL'}  ${name}`);
  for (const c of failed) console.log(`        x ${c.what}${c.got !== undefined ? `  (got: ${c.got})` : ''}`);
}
const check = (what, ok, got) => ({ what, ok: !!ok, got });

async function expectAllowed(name, { persona, hint, tenantId, tenantDomain, email, idpSub }) {
  const since = new Date().toISOString();
  const r = await login({ persona, hint });
  const checks = [check('flow ended with an authorization code', r.outcome === 'code', JSON.stringify(r))];
  if (r.outcome === 'code') {
    const t = await redeem(r);
    checks.push(check(`access token tenant_id = ${tenantId}`, t.access.tenant_id === tenantId, t.access.tenant_id));
    checks.push(check(`access token tenant_domain = ${tenantDomain}`, t.access.tenant_domain === tenantDomain, t.access.tenant_domain));
    checks.push(check('id token carries the same tenant_id', t.id.tenant_id === tenantId, t.id.tenant_id));
    checks.push(check('access token idp = mock-google', t.access.idp === 'mock-google', t.access.idp));
    checks.push(check(`access token idp_sub = ${idpSub} (the provider's own subject, not the Keycloak sub)`, t.access.idp_sub === idpSub && t.access.idp_sub !== t.access.sub, `${t.access.idp_sub} / ${t.access.sub}`));
    const u = await userByEmail(email.toLowerCase());
    checks.push(check('Keycloak user exists', !!u));
    checks.push(check('user attribute tenant_id stored', u?.attributes?.tenant_id?.[0] === tenantId, JSON.stringify(u?.attributes)));
    checks.push(check('user attributes idp_alias / idp_subject stored', u?.attributes?.idp_alias?.[0] === 'mock-google' && u?.attributes?.idp_subject?.[0] === idpSub, JSON.stringify(u?.attributes)));
    checks.push(check('log shows TENANT_RESOLVED', logsSince(since).includes(`TENANT_RESOLVED tenant=${tenantId}`)));
    return { r, t, checks: (record(name, checks), checks) };
  }
  record(name, checks);
  return { r };
}

async function expectDenied(name, { persona, hint, reason, emailForUserCheck, expectUserCountUnchanged }) {
  const before = (await users()).length;
  const since = new Date().toISOString();
  const r = await login({ persona, hint });
  const log = logsSince(since);
  const checks = [
    check('no authorization code was issued', r.outcome !== 'code', JSON.stringify(r)),
    check('user saw a 403 error page', r.outcome === 'page' && r.status === 403, `${r.outcome}/${r.status}`),
    check(`SPI logged TENANT_DENIED reason=${reason}`, new RegExp(`TENANT_DENIED reason=${reason}\\b`).test(log)),
  ];
  if (emailForUserCheck) {
    checks.push(check('no Keycloak user was created for this identity', !(await userByEmail(emailForUserCheck))));
  }
  if (expectUserCountUnchanged) {
    checks.push(check('user count unchanged', (await users()).length === before, `${before} -> ${(await users()).length}`));
  }
  record(name, checks);
  return r;
}

// ---------- scenarios ----------
async function main() {
  TOKEN = await adminToken();
  await wipeUsers();
  console.log(`\nspike-mt end-to-end (${new Date().toISOString()})\n`);

  // --- allowed ---
  await expectAllowed('ALLOW   known tenant acme.com (alice)', {
    persona: 'alice', hint: 'alice@acme.com', tenantId: 't-acme', tenantDomain: 'acme.com', email: 'alice@acme.com' , idpSub: 'g-alice' });
  await expectAllowed('ALLOW   known tenant globex.com (bob)', {
    persona: 'bob', hint: 'bob@globex.com', tenantId: 't-globex', tenantDomain: 'globex.com', email: 'bob@globex.com' , idpSub: 'g-bob' });
  const usersBefore = (await users()).length;
  await expectAllowed('ALLOW   returning user, same tenant (alice again)', {
    persona: 'alice', hint: 'alice@acme.com', tenantId: 't-acme', tenantDomain: 'acme.com', email: 'alice@acme.com' , idpSub: 'g-alice' });
  record('ALLOW   returning user did not create a duplicate', [
    check('user count unchanged', (await users()).length === usersBefore, `${usersBefore} -> ${(await users()).length}`)]);
  await expectAllowed('ALLOW   hd/email case is normalised (ACME.COM)', {
    persona: 'upper', hint: 'upper@acme.com', tenantId: 't-acme', tenantDomain: 'acme.com', email: 'upper@acme.com' , idpSub: 'g-upper' });
  await expectAllowed('ALLOW   no discovery hint is fine (alice, no hint)', {
    persona: 'alice', hint: undefined, tenantId: 't-acme', tenantDomain: 'acme.com', email: 'alice@acme.com' , idpSub: 'g-alice' });

  // --- denied ---
  await expectDenied('DENY    unknown domain (carol@unknown-corp.com)', {
    persona: 'carol', hint: 'carol@unknown-corp.com', reason: 'UNKNOWN_DOMAIN', emailForUserCheck: 'carol@unknown-corp.com' });
  await expectDenied('DENY    consumer account without hd (eve@gmail.com)', {
    persona: 'eve', hint: 'eve@gmail.com', reason: 'MISSING_HD', emailForUserCheck: 'eve@gmail.com' });
  await expectDenied('DENY    suspended tenant (dave@initech.com)', {
    persona: 'dave', hint: 'dave@initech.com', reason: 'TENANT_SUSPENDED', emailForUserCheck: 'dave@initech.com' });
  await expectDenied('DENY    SSO disabled for tenant (hank@hooli.com)', {
    persona: 'hank', hint: 'hank@hooli.com', reason: 'SSO_DISABLED', emailForUserCheck: 'hank@hooli.com' });
  await expectDenied('DENY    email not verified (frank@acme.com)', {
    persona: 'frank', hint: 'frank@acme.com', reason: 'EMAIL_NOT_VERIFIED', emailForUserCheck: 'frank@acme.com' });
  await expectDenied('DENY    email domain belongs to another tenant (mallory)', {
    persona: 'mallory', hint: 'mallory@globex.com', reason: 'EMAIL_DOMAIN_MISMATCH', emailForUserCheck: 'mallory@globex.com' });
  await expectDenied('DENY    discovered tenant != authenticated tenant (hint acme, hd globex)', {
    persona: 'zed', hint: 'zed@acme.com', reason: 'HINT_MISMATCH', emailForUserCheck: 'zed@globex.com' });
  await expectDenied('DENY    domain claimed by two tenants (dup.com)', {
    persona: 'dupuser', hint: 'dupuser@dup.com', reason: 'AMBIGUOUS_DOMAIN', emailForUserCheck: 'dupuser@dup.com' });
  await expectDenied('DENY    look-alike domain acme.com.evil.com', {
    persona: 'trap', hint: 'trap@acme.com.evil.com', reason: 'UNKNOWN_DOMAIN', emailForUserCheck: 'trap@acme.com.evil.com' });

  // --- existing user bound to another tenant ---
  await admin('POST', '/users', {
    username: 'conflict@acme.com', email: 'conflict@acme.com', emailVerified: true, enabled: true,
    firstName: 'Conflict', lastName: 'Tester',
    attributes: { tenant_id: ['t-globex'], tenant_domain: ['globex.com'] },
    federatedIdentities: [{ identityProvider: 'mock-google', userId: 'g-conflict', userName: 'conflict@acme.com' }],
  });
  await expectDenied('DENY    existing user bound to t-globex now presents hd=acme.com', {
    persona: 'conflict', hint: 'conflict@acme.com', reason: 'USER_TENANT_CONFLICT', expectUserCountUnchanged: true });
  const bound = await userByEmail('conflict@acme.com');
  record('DENY    conflicting user kept its original tenant binding', [
    check('tenant_id still t-globex', bound?.attributes?.tenant_id?.[0] === 't-globex', JSON.stringify(bound?.attributes))]);

  // --- existing user recorded for a different provider identity ---
  await admin('POST', '/users', {
    username: 'zed@globex.com', email: 'zed@globex.com', emailVerified: true, enabled: true, firstName: 'Zed', lastName: 'Tester',
    attributes: { tenant_id: ['t-globex'], tenant_domain: ['globex.com'], idp_alias: ['mock-google'], idp_subject: ['g-impostor'] },
    federatedIdentities: [{ identityProvider: 'mock-google', userId: 'g-zed', userName: 'zed@globex.com' }],
  });
  await expectDenied('DENY    existing user recorded for another provider subject', {
    persona: 'zed', hint: 'zed@globex.com', reason: 'USER_IDENTITY_CONFLICT', expectUserCountUnchanged: true });

  // --- users cannot rewrite their own tenant or identity ---
  const alice = await login({ persona: 'alice', hint: 'alice@acme.com' });
  const aliceTok = await redeem(alice);
  const spoof = await fetch(`${KC}/realms/${REALM}/account`, {
    method: 'POST',
    headers: { authorization: `Bearer ${aliceTok.raw.access_token}`, 'content-type': 'application/json' },
    body: JSON.stringify({ username: 'alice@acme.com', email: 'alice@acme.com', firstName: 'alice', lastName: 'Tester',
      attributes: { tenant_id: ['t-globex'], tenant_domain: ['globex.com'], idp_alias: ['mock-google'], idp_subject: ['g-bob'] } }),
  });
  const spoofBody = await spoof.text();
  const aliceUser = await userByEmail('alice@acme.com');
  const again = await redeem(await login({ persona: 'alice', hint: 'alice@acme.com' }));
  record('SPOOF   user cannot change own tenant or provider identity via the account API', [
    check('account API rejected the write as read-only (400)',
      spoof.status === 400 && spoofBody.includes('error-user-attribute-read-only'), `HTTP ${spoof.status} ${spoofBody.slice(0, 80)}`),
    check('stored tenant_id is still t-acme', aliceUser?.attributes?.tenant_id?.[0] === 't-acme', JSON.stringify(aliceUser?.attributes)),
    check('stored idp_subject is still g-alice', aliceUser?.attributes?.idp_subject?.[0] === 'g-alice', JSON.stringify(aliceUser?.attributes)),
    check('next token still has tenant_id t-acme and idp_sub g-alice', again.access.tenant_id === 't-acme' && again.access.idp_sub === 'g-alice', `${again.access.tenant_id} / ${again.access.idp_sub}`),
  ]);

  // --- registry hot reload: suspend acme, then restore ---
  const original = fs.readFileSync(REGISTRY_FILE, 'utf8');
  try {
    const suspended = JSON.parse(original);
    suspended.tenants.find((t) => t.tenantId === 't-acme').status = 'suspended';
    fs.writeFileSync(REGISTRY_FILE, JSON.stringify(suspended, null, 2));
    await new Promise((r) => setTimeout(r, 2500));
    await expectDenied('RELOAD  tenant suspended in registry takes effect without restart', {
      persona: 'alice', hint: 'alice@acme.com', reason: 'TENANT_SUSPENDED' });
  } finally {
    fs.writeFileSync(REGISTRY_FILE, original);
  }
  await new Promise((r) => setTimeout(r, 2500));
  await expectAllowed('RELOAD  tenant re-activated in registry is allowed again', {
    persona: 'alice', hint: 'alice@acme.com', tenantId: 't-acme', tenantDomain: 'acme.com', email: 'alice@acme.com' , idpSub: 'g-alice' });

  const failed = results.filter((r) => !r.ok);
  console.log(`\n${results.length - failed.length}/${results.length} scenarios passed`);
  process.exit(failed.length ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(2); });
