// Proves the hub-and-spoke chain AND the per-realm tenant gate on the harness Keycloak (8380), without Google:
//   <tenant realm> (google-hub)  ->  master  ->  [a LOCAL master user stands in for the Google sign-in]  ->  back
// The stand-in users carry the same attributes the Google IdP mappers would set in master (google_hd, google_sub,
// google_email_verified), so everything after Google is exercised for real: the broker client and its redirect URIs, the
// Docker-internal server-to-server calls, claim propagation through both hops, the tenant gate, user creation, the JWT
// and federated logout. What it cannot prove is Google itself (Hosted Domain, the real hd/sub values).
//
//   docker compose up -d spike-keycloak        (rebuild first if the plugin changed: docker compose build spike-keycloak)
//   node scripts/hub-and-spoke-e2e.mjs         (it runs scripts/setup-tenant.mjs itself, for two tenants)

import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { Jar, decode } from './lib/browser.mjs';

const KC = process.env.KC_URL ?? 'http://localhost:8380';
const REDIRECT = 'http://localhost:5173/cb';
const SETUP = new URL('../../scripts/setup-tenant.mjs', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
const STARTED = new Date().toISOString();

const results = [];
const check = (name, ok, detail = '') => { results.push(ok); console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? `  (${detail})` : ''}`); };

// ---- Keycloak admin ------------------------------------------------------------------------------------------------
const admin = (await (await fetch(`${KC}/realms/master/protocol/openid-connect/token`, {
  method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({ grant_type: 'password', client_id: 'admin-cli', username: 'admin', password: 'admin' }),
})).json()).access_token;
const api = async (method, path, body) => {
  const res = await fetch(`${KC}/admin/realms${path}`, { method, headers: { authorization: `Bearer ${admin}`, 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await res.text();
  return { status: res.status, json: text ? JSON.parse(text) : null };
};

const setup = (...args) => {
  try {
    return { ok: true, out: execFileSync('node', [SETUP, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, KC_URL: KC, KC_INTERNAL_URL: 'http://localhost:8080', MASTER_HINT: 'none',
        GOOGLE_CLIENT_ID: 'x', GOOGLE_CLIENT_SECRET: 'x' } }) };
  } catch (e) { return { ok: false, out: `${e.stdout ?? ''}${e.stderr ?? ''}` }; }
};

// ---- the browser journey, as a function ----------------------------------------------------------------------------
/** Stand-in "Google" user in master. Undefined attributes are left out (a missing claim is a scenario). */
async function masterUser(name, { hd, sub, verified, email }) {
  const found = (await api('GET', `/master/users?username=${name}&exact=true`)).json ?? [];
  for (const u of found) await api('DELETE', `/master/users/${u.id}`);
  const attributes = {};
  if (hd !== undefined) attributes.google_hd = [hd];
  if (sub !== undefined) attributes.google_sub = [sub];
  if (verified !== undefined) attributes.google_email_verified = [String(verified)];
  const res = await api('POST', '/master/users', { username: name, email, firstName: 'Hub', lastName: name, enabled: true,
    emailVerified: true, attributes, credentials: [{ type: 'password', value: 'hub-pw', temporary: false }] });
  if (res.status !== 201) throw new Error(`could not create master user ${name}: HTTP ${res.status} ${JSON.stringify(res.json)}`);
}

/** Sign in to `realm` through google-hub as master user `name`. Resolves { code, status, path, jar, verifier, last }. */
async function signIn(realm, name) {
  const jar = new Jar();
  const verifier = crypto.randomBytes(32).toString('base64url');
  const params = new URLSearchParams({
    client_id: 'google-oidc-poc-frontend', redirect_uri: REDIRECT, response_type: 'code', scope: 'openid',
    state: crypto.randomUUID(), nonce: crypto.randomUUID(), kc_idp_hint: 'google-hub',
    code_challenge: crypto.createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256',
  });
  let url = `${KC}/realms/${realm}/protocol/openid-connect/auth?${params}`;
  const path = [];
  let posted = false, status = 0, last = '';
  for (let hop = 0; hop < 25; hop++) {
    const res = await fetch(url, { redirect: 'manual', headers: { cookie: jar.header(url) } });
    jar.store(url, res);
    status = res.status;
    path.push(`${res.status} ${new URL(url).pathname}`);
    if (res.status >= 300 && res.status < 400) {
      const next = new URL(res.headers.get('location'), url).toString();
      if (next.startsWith(REDIRECT)) return { code: new URL(next).searchParams.get('code'), status, path, jar, verifier, last };
      url = next; continue;
    }
    const html = await res.text();
    last = html.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 160);
    const form = html.match(/<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"/);
    if (form && !posted) {                           // master's login page: sign in as the stand-in user
      const action = form[1].replace(/&amp;/g, '&');
      const post = await fetch(action, { method: 'POST', redirect: 'manual',
        headers: { cookie: jar.header(action), 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ username: name, password: 'hub-pw', credentialId: '' }) });
      jar.store(action, post);
      posted = true;
      path.push(`POST ${post.status} master login`);
      if (!post.headers.get('location')) { status = post.status; break; }
      url = new URL(post.headers.get('location'), action).toString();
      continue;
    }
    break;
  }
  return { code: null, status, path, jar, verifier, last };
}

async function redeem(realm, attempt) {
  const res = await fetch(`${KC}/realms/${realm}/protocol/openid-connect/token`, {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'authorization_code', client_id: 'google-oidc-poc-frontend', code: attempt.code,
      redirect_uri: REDIRECT, code_verifier: attempt.verifier }) });
  const json = await res.json();
  return { ok: res.ok, tokens: json, claims: res.ok ? decode(json.access_token) : {}, error: json.error_description };
}
const usersByEmail = async (realm, email) => (await api('GET', `/${realm}/users?email=${encodeURIComponent(email)}&exact=true`)).json ?? [];

// ---- 0. set up two tenants with the script under test ---------------------------------------------------------------
console.log('--- setup (scripts/setup-tenant.mjs)');
for (const realm of ['yserious', 'acme']) await api('DELETE', `/${realm}`);   // a clean slate; master's IdP is shared and kept
const s1 = setup('--id', 'yserious', '--domain', 'yserious.com');
check('setup-tenant: yserious', s1.ok, s1.ok ? '' : s1.out.slice(-300));
const s2 = setup('--id', 'acme', '--domain', 'acme.com', '--domain', 'acme.co.uk');
check('setup-tenant: acme (primary + secondary domain)', s2.ok, s2.ok ? '' : s2.out.slice(-300));
const s3 = setup('--id', 'yserious', '--domain', 'yserious.com');
check('setup-tenant is idempotent (second run changes nothing)', s3.ok && /tenant gate already present/.test(s3.out) && /already present/.test(s3.out), s3.ok ? '' : s3.out.slice(-200));
if (!s1.ok || !s2.ok) { console.log(s1.out, s2.out); process.exit(1); }

// ---- 1. the allowed path ---------------------------------------------------------------------------------------------
console.log('--- allowed');
const SUB = '112233445566778899001';
await masterUser('hub-ok', { hd: 'yserious.com', sub: SUB, verified: true, email: 'hub-ok@yserious.com' });
for (const u of await usersByEmail('yserious', 'hub-ok@yserious.com')) await api('DELETE', `/yserious/users/${u.id}`);
const ok = await signIn('yserious', 'hub-ok');
console.log('path: ' + ok.path.join(' -> '));
check('yserious user signs in through google-hub and master', !!ok.code, ok.code ? '' : `stopped (${ok.status}): ${ok.last}`);
if (ok.code) {
  const t = await redeem('yserious', ok);
  check('code redeemed at yserious', t.ok, t.error ?? '');
  check('issuer is the yserious realm', (t.claims.iss ?? '').endsWith('/realms/yserious'));
  check('idp_sub carries the Google subject through both hops', t.claims.idp_sub === SUB, t.claims.idp_sub);
  check('tenant_id / tenant_domain / idp constants', t.claims.tenant_id === 't-yserious' && t.claims.tenant_domain === 'yserious.com' && t.claims.idp === 'google');
  check('audience oidc-poc-api present', [].concat(t.claims.aud ?? []).includes('oidc-poc-api'));
  const u = (await usersByEmail('yserious', 'hub-ok@yserious.com'))[0];
  check('user created in yserious with google_hd, google_sub, google_email_verified',
    u?.attributes?.google_hd?.[0] === 'yserious.com' && u?.attributes?.google_sub?.[0] === SUB && u?.attributes?.google_email_verified?.[0] === 'true',
    JSON.stringify(u?.attributes ?? {}));
  const links = u ? (await api('GET', `/yserious/users/${u.id}/federated-identity`)).json : [];
  check('user is linked through google-hub', links.some((l) => l.identityProvider === 'google-hub'));

  // Federated logout: logging out of the tenant realm also calls master's logout endpoint.
  let logoutUrl = `${KC}/realms/yserious/protocol/openid-connect/logout?` + new URLSearchParams({
    id_token_hint: t.tokens.id_token, post_logout_redirect_uri: 'http://localhost:5173/' });
  let landed = false, why = '';
  for (let hop = 0; hop < 15; hop++) {
    const res = await fetch(logoutUrl, { redirect: 'manual', headers: { cookie: ok.jar.header(logoutUrl) } });
    ok.jar.store(logoutUrl, res);
    if (res.status >= 300 && res.status < 400) {
      const next = new URL(res.headers.get('location'), logoutUrl).toString();
      if (next.startsWith('http://localhost:5173/')) { landed = true; break; }
      logoutUrl = next; continue;
    }
    why = (await res.text()).replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').slice(0, 160);
    break;
  }
  check('federated logout returns the browser to the app', landed, why);
}

console.log('--- the second tenant, and the gate keeping tenants apart');
await masterUser('hub-acme', { hd: 'acme.com', sub: '223344556677889900112', verified: true, email: 'hub-acme@acme.com' });
const acmeOk = await signIn('acme', 'hub-acme');
check('acme user signs in to realm acme', !!acmeOk.code, acmeOk.code ? '' : `stopped (${acmeOk.status}): ${acmeOk.last}`);
if (acmeOk.code) {
  const t = await redeem('acme', acmeOk);
  check('acme token: issuer acme, tenant_id t-acme', (t.claims.iss ?? '').endsWith('/realms/acme') && t.claims.tenant_id === 't-acme', t.claims.tenant_id);
}
await masterUser('hub-acme2', { hd: 'acme.com', sub: '223344556677889900113', verified: true, email: 'hub-acme2@acme.co.uk' });
const secondary = await signIn('acme', 'hub-acme2');
check('acme user on a bound secondary domain (hd acme.com, email @acme.co.uk) is allowed', !!secondary.code, secondary.code ? '' : `stopped: ${secondary.last}`);

// ---- 2. the denials ------------------------------------------------------------------------------------------------
console.log('--- denied');
async function expectDenied(label, realm, name, email) {
  const attempt = await signIn(realm, name);
  const created = await usersByEmail(realm, email);
  check(`${label}: refused (403, no code)`, !attempt.code && attempt.status === 403, `status ${attempt.status}, code ${attempt.code ? 'ISSUED' : 'none'}`);
  check(`${label}: no user left behind in ${realm}`, created.length === 0, `${created.length} user(s)`);
}
await masterUser('hub-cross', { hd: 'acme.com', sub: '300000000000000000001', verified: true, email: 'hub-cross@acme.com' });
await expectDenied('acme account into the yserious realm', 'yserious', 'hub-cross', 'hub-cross@acme.com');
await masterUser('hub-cross2', { hd: 'yserious.com', sub: '300000000000000000002', verified: true, email: 'hub-cross2@yserious.com' });
await expectDenied('yserious account into the acme realm', 'acme', 'hub-cross2', 'hub-cross2@yserious.com');
await masterUser('hub-unverified', { hd: 'yserious.com', sub: '300000000000000000003', verified: false, email: 'hub-unverified@yserious.com' });
await expectDenied('unverified email', 'yserious', 'hub-unverified', 'hub-unverified@yserious.com');
await masterUser('hub-nohd', { sub: '300000000000000000004', verified: true, email: 'hub-nohd@yserious.com' });
await expectDenied('no hd claim (a personal account would look like this)', 'yserious', 'hub-nohd', 'hub-nohd@yserious.com');
await masterUser('hub-gmail', { hd: 'yserious.com', sub: '300000000000000000005', verified: true, email: 'hub-gmail@gmail.com' });
await expectDenied('hd of the tenant but an email outside its domains', 'yserious', 'hub-gmail', 'hub-gmail@gmail.com');
await masterUser('hub-nosub', { hd: 'yserious.com', verified: true, email: 'hub-nosub@yserious.com' });
await expectDenied('no stable Google subject', 'yserious', 'hub-nosub', 'hub-nosub@yserious.com');
await masterUser('hub-noverified', { hd: 'yserious.com', sub: '300000000000000000006', email: 'hub-noverified@yserious.com' });
await expectDenied('email_verified not propagated at all', 'yserious', 'hub-noverified', 'hub-noverified@yserious.com');

// A person already known in the realm presents a different Google subject.
await masterUser('hub-conflict', { hd: 'yserious.com', sub: '400000000000000000001', verified: true, email: 'hub-conflict@yserious.com' });
const first = await signIn('yserious', 'hub-conflict');
check('subject-conflict setup: first sign-in allowed', !!first.code);
const mu = (await api('GET', '/master/users?username=hub-conflict&exact=true')).json[0];
await api('PUT', `/master/users/${mu.id}`, { ...mu, attributes: { ...mu.attributes, google_sub: ['400000000000000000999'] } });
const second = await signIn('yserious', 'hub-conflict');
check('same person, different Google subject: refused', !second.code && second.status === 403, `status ${second.status}`);

// The master hop itself: only the registered redirect URI is accepted.
const bad = await fetch(`${KC}/realms/master/protocol/openid-connect/auth?` + new URLSearchParams({
  client_id: 'broker-for-yserious', redirect_uri: 'http://localhost:9999/evil', response_type: 'code', scope: 'openid' }), { redirect: 'manual' });
check('master refuses an unregistered redirect URI for the broker client', bad.status >= 400 || /Invalid parameter: redirect_uri/i.test(await bad.text()), `HTTP ${bad.status}`);

// ---- 2b. negative control: the denials above are the gate's doing, and a realm WITHOUT a gate admits anyone master admits --
console.log('--- control (gate removed, then restored)');
const chk = setup('--id', 'yserious', '--check');
check('--check passes for a properly set up tenant', chk.ok && /all present/.test(chk.out), chk.ok ? '' : chk.out.slice(-200));
const gateMapper = (await api('GET', '/yserious/identity-provider/instances/google-hub/mappers')).json.find((m) => m.identityProviderMapper === 'hub-tenant-gate-mapper');
await api('DELETE', `/yserious/identity-provider/instances/google-hub/mappers/${gateMapper.id}`);
const noGateCheck = setup('--id', 'yserious', '--check');
check('--check reports a realm whose gate is missing (exit 1)', !noGateCheck.ok && /MISSING.*tenant gate/.test(noGateCheck.out));
await masterUser('hub-control', { hd: 'acme.com', sub: '500000000000000000001', verified: true, email: 'hub-control@acme.com' });
const control = await signIn('yserious', 'hub-control');
check('CONTROL: without the gate an acme account IS admitted to yserious (proves the gate is what blocks it)', !!control.code, `status ${control.status}`);
for (const u of await usersByEmail('yserious', 'hub-control@acme.com')) await api('DELETE', `/yserious/users/${u.id}`);
const restore = setup('--id', 'yserious', '--domain', 'yserious.com');
check('setup-tenant restores the gate', restore.ok && /tenant gate created/.test(restore.out), restore.ok ? '' : restore.out.slice(-200));
await masterUser('hub-after', { hd: 'acme.com', sub: '500000000000000000002', verified: true, email: 'hub-after@acme.com' });
const after = await signIn('yserious', 'hub-after');
check('after restoring the gate the same account is refused again', !after.code && after.status === 403, `status ${after.status}`);

// ---- 3. the reasons in the Keycloak log -------------------------------------------------------------------------------
console.log('--- log');
const log = execFileSync('docker', ['logs', 'spike-keycloak', '--since', STARTED], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 64 * 1024 * 1024 });
for (const reason of ['HD_NOT_ALLOWED', 'EMAIL_NOT_VERIFIED', 'NO_HD', 'EMAIL_DOMAIN_NOT_ALLOWED', 'NO_SUBJECT', 'SUBJECT_CONFLICT']) {
  check(`log shows TENANT_DENIED gate=hub reason=${reason}`, new RegExp(`TENANT_DENIED gate=hub .*reason=${reason}`).test(log));
}

const failed = results.filter((r) => !r).length;
console.log(`\n${results.length - failed}/${results.length} checks passed`);
process.exit(failed ? 1 : 0);
