// Adversarial / identity-lifecycle scenarios against the spike Keycloak. They are written as CHARACTERIZATIONS: each
// records what the system actually does, labelled
//     OK   behaves as designed
//     GAP  a weakness or missing control (details printed)
//     INFO an observation that matters for design decisions
// so the findings in docs/architecture_validation.md can be reproduced and regressions in the fixes show up as GAPs.
//
// Prereqs: harness up (docker compose up -d --build), mock IdP running, `node scripts/setup-realm.mjs` done.
// Usage:   node scripts/e2e-attacks.mjs        (exit code 1 if any GAP)

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { KC, REALM, adminToken } from './setup-realm.mjs';
import { Jar, decode } from './flow.mjs';

const REDIRECT = 'http://localhost:5174/cb';
const REGISTRY_FILE = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'tenant-registry.json');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------- browser flow with full outcome detail ----------
async function loginRaw({ persona, hint, clientId = 'spike-app', extra = {}, jar = new Jar(), prompt }) {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  const params = new URLSearchParams({
    client_id: clientId, redirect_uri: REDIRECT, response_type: 'code', scope: 'openid',
    state: crypto.randomUUID(), nonce: crypto.randomUUID(),
    code_challenge: challenge, code_challenge_method: 'S256', kc_idp_hint: 'mock-google', ...extra,
  });
  if (hint) params.set('login_hint', hint);
  if (prompt) params.set('prompt', prompt);

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
        if (q.get('error')) return { outcome: 'error', error: q.get('error'), jar };
        return { outcome: 'code', code: q.get('code'), verifier, jar };
      }
      url = next;
      continue;
    }
    const body = await res.text();
    const text = body.replace(/<script[\s\S]*?<\/script>/g, '').replace(/<style[\s\S]*?<\/style>/g, '')
      .replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
    return { outcome: 'page', status: res.status, text: text.slice(0, 260), jar };
  }
  return { outcome: 'page', status: 0, text: 'too many redirects', jar };
}

/** Exchanges a code; never throws: returns { ok, status, json, claims? }. */
async function exchange({ code, verifier, clientId = 'spike-app' }) {
  const res = await fetch(`${KC}/realms/${REALM}/protocol/openid-connect/token`, {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'authorization_code', client_id: clientId, code, redirect_uri: REDIRECT, code_verifier: verifier }),
  });
  const json = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, json, claims: res.ok ? decode(json.access_token) : undefined };
}
const mustExchange = async (r) => {
  const t = await exchange(r);
  if (!t.ok) throw new Error(`token exchange failed: ${JSON.stringify(t.json)}`);
  return { ...t.json, claims: t.claims };
};

async function refresh(refreshToken, clientId = 'spike-app') {
  const res = await fetch(`${KC}/realms/${REALM}/protocol/openid-connect/token`, {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'refresh_token', client_id: clientId, refresh_token: refreshToken }),
  });
  return { status: res.status, json: await res.json().catch(() => ({})) };
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
const userByEmail = async (email) => (await admin('GET', `/users?email=${encodeURIComponent(email)}&exact=true`))[0];
const logsSince = (iso) => execSync(`docker logs spike-keycloak --since ${iso} 2>&1`, { encoding: 'utf8', maxBuffer: 20e6 });

// ---------- reporting ----------
const findings = [];
function report(kind, name, detail) {
  findings.push({ kind, name });
  console.log(`${kind.padEnd(4)} ${name}`);
  if (detail) console.log(`       ${detail}`);
}
async function scenario(name, fn) {
  try { await fn(); } catch (e) { report('GAP', `${name} (scenario errored)`, String(e.message ?? e).slice(0, 300)); }
}

async function main() {
  TOKEN = await adminToken();
  for (const u of await users()) await admin('DELETE', `/users/${u.id}`);
  console.log(`\nadversarial scenarios against spike-mt (${new Date().toISOString()})\n`);
  const originalRegistry = fs.readFileSync(REGISTRY_FILE, 'utf8');

  try {
    // ===== A. who can authenticate =====
    await scenario('client-supplied hd', async () => {
      const since = new Date().toISOString();
      const r = await loginRaw({ persona: 'eve', hint: 'eve@acme.com', extra: { hd: 'acme.com' } });
      const denied = r.outcome === 'page' && r.status === 403 && /TENANT_DENIED reason=MISSING_HD/.test(logsSince(since));
      report(denied ? 'OK' : 'GAP', 'a client-supplied hd=acme.com parameter cannot rescue a consumer account (token has no hd)',
        denied ? 'tenant comes from the signed ID token, never from the request' : JSON.stringify(r));
    });

    await scenario('unmanaged corporate address', async () => {
      const since = new Date().toISOString();
      const r = await loginRaw({ persona: 'unmanaged', hint: 'ceo@acme.com' });
      const denied = r.outcome === 'page' && r.status === 403 && /MISSING_HD/.test(logsSince(since)) && !(await userByEmail('ceo@acme.com'));
      report(denied ? 'OK' : 'GAP', 'a consumer Google account registered with a corporate address (verified email, no hd) is rejected',
        denied ? 'email_verified=true and an acme.com address are NOT enough; hd is what proves a managed org account' : JSON.stringify(r));
    });

    // ===== identity key =====
    let aliceKcSub1;
    await scenario('provider claims', async () => {
      const t = await mustExchange(await loginRaw({ persona: 'alice', hint: 'alice@acme.com' }));
      aliceKcSub1 = t.claims.sub;
      const ok = t.claims.idp === 'mock-google' && t.claims.idp_sub === 'g-alice';
      report(ok ? 'OK' : 'GAP', 'the token carries the provider alias and the provider\'s own subject (stamped by the SPI, not a session note)',
        `idp=${t.claims.idp}  idp_sub=${t.claims.idp_sub}  (keycloak sub=${t.claims.sub})`);
    });

    await scenario('stable identity after re-link', async () => {
      const u = await userByEmail('alice@acme.com');
      await admin('DELETE', `/users/${u.id}`); // e.g. an admin clean-up
      const t = await mustExchange(await loginRaw({ persona: 'alice', hint: 'alice@acme.com' }));
      const kcChanged = t.claims.sub !== aliceKcSub1;
      report(t.claims.idp_sub === 'g-alice' ? 'OK' : 'GAP',
        'the person key (idp, idp_sub) survives deleting and re-linking the Keycloak user',
        `keycloak sub ${kcChanged ? 'CHANGED' : 'unchanged'} (${aliceKcSub1} -> ${t.claims.sub}); idp_sub stayed ${t.claims.idp_sub}. Keying on idp_sub keeps the app identity.`);
    });

    // ===== C. identity lifecycle =====
    await scenario('recreated account', async () => {
      const since = new Date().toISOString();
      const before = await userByEmail('alice@acme.com');
      const count = (await users()).length;
      const r = await loginRaw({ persona: 'alice2', hint: 'alice@acme.com' }); // same email, NEW Google sub
      const denied = r.outcome === 'page' && r.status === 403 && /TENANT_DENIED reason=EXISTING_ACCOUNT_NOT_LINKED/.test(logsSince(since));
      const untouched = (await users()).length === count && (await userByEmail('alice@acme.com'))?.id === before.id;
      if (r.outcome === 'code') {
        const t = await exchange(r);
        report('GAP', 'ACCOUNT TAKEOVER: a recreated Google account (new sub, same email) was signed in', `token sub ${t.claims?.sub} (old user ${before.id})`);
      } else {
        report(denied && untouched ? 'OK' : 'GAP',
          'a recreated Google account (new sub, same email) is denied with a clear reason and is never linked to the old user',
          `outcome=${r.outcome}/${r.status ?? ''} reason logged=${denied} old user untouched=${untouched}; page: "${(r.text ?? '').slice(0, 90)}"`);
      }
    });

    await scenario('renamed email', async () => {
      const before = await userByEmail('alice@acme.com');
      const count = (await users()).length;
      const r = await loginRaw({ persona: 'aliceRenamed', hint: 'alice.new@acme.com' }); // same sub, new email
      if (r.outcome !== 'code') { report('GAP', 'a renamed Google email (same sub) cannot sign in', `outcome=${r.outcome} ${r.text ?? r.error}`); return; }
      const t = await mustExchange(r);
      const after = await admin('GET', `/users/${before.id}`);
      const sameUser = t.claims.sub === before.id && (await users()).length === count && t.claims.idp_sub === 'g-alice';
      report(sameUser ? 'OK' : 'GAP', 'a renamed email (same Google sub) stays the same Keycloak user, tenant and identity',
        `email ${before.email} -> ${after.email}, username "${after.username}", tenant_id=${t.claims.tenant_id}, idp_sub=${t.claims.idp_sub}`);
    });

    // ===== C. aliases and secondary domains =====
    await scenario('secondary domains', async () => {
      const sam = await mustExchange(await loginRaw({ persona: 'sam', hint: 'sam@acme.co.uk' }));
      report(sam.claims.tenant_id === 't-acme' ? 'OK' : 'GAP', 'a user whose email is on the tenant\'s secondary domain (hd = primary) maps to the tenant',
        `tenant_id=${sam.claims.tenant_id} tenant_domain=${sam.claims.tenant_domain}`);
      const sec = await mustExchange(await loginRaw({ persona: 'sec', hint: 'pat@acme.com' }));
      report('INFO', 'tenant_domain is NOT canonical within a tenant: it carries whatever hd the user presented',
        `t-acme users carry tenant_domain = ${sam.claims.tenant_domain} and ${sec.claims.tenant_domain}. Use tenant_id as the key, never tenant_domain.`);
    });

    // ===== E. suspension vs. already-issued sessions =====
    await scenario('suspension', async () => {
      const jar = new Jar();
      const t0 = await mustExchange(await loginRaw({ persona: 'bob', hint: 'bob@globex.com', jar }));
      const suspended = JSON.parse(originalRegistry);
      suspended.tenants.find((t) => t.tenantId === 't-globex').status = 'suspended';
      fs.writeFileSync(REGISTRY_FILE, JSON.stringify(suspended, null, 2));
      await sleep(2500);

      const since = new Date().toISOString();
      const fresh = await loginRaw({ persona: 'bob', hint: 'bob@globex.com' });
      report(fresh.outcome === 'page' && fresh.status === 403 ? 'OK' : 'GAP',
        'after suspension a NEW sign-in is denied', `outcome=${fresh.outcome}/${fresh.status ?? ''}`);

      const viaRefresh = await refresh(t0.refresh_token);
      report(viaRefresh.status === 200 ? 'GAP' : 'OK',
        viaRefresh.status === 200 ? 'after suspension the REFRESH TOKEN still mints access tokens'
                                  : 'after suspension the refresh token no longer yields tokens (token-time guard), with NO session revocation',
        `refresh -> HTTP ${viaRefresh.status} ${viaRefresh.json.error ?? ''}; log TENANT_TOKEN_REFUSED=${/TENANT_TOKEN_REFUSED reason=TENANT_SUSPENDED/.test(logsSince(since))}`);

      const silent = await loginRaw({ persona: 'bob', hint: 'bob@globex.com', jar, prompt: 'none' });
      const viaSso = silent.outcome === 'code' ? await exchange(silent) : { ok: false };
      report(viaSso.ok ? 'GAP' : 'OK',
        viaSso.ok ? 'after suspension the existing SSO session still yields a TOKEN silently'
                  : 'after suspension the existing SSO session yields no token',
        `silent re-authentication -> ${silent.outcome}${silent.outcome === 'code' ? `, token exchange HTTP ${viaSso.status}` : ''}`);

      // Defence in depth: revoking the tenant's sessions (what tenant.mjs suspend does) also ends them.
      for (const u of await users()) if ((u.attributes?.tenant_id ?? [])[0] === 't-globex') await admin('POST', `/users/${u.id}/logout`);
      const afterRevoke = await refresh(t0.refresh_token);
      report(afterRevoke.status !== 200 ? 'OK' : 'GAP', 'revoking the tenant\'s Keycloak sessions on suspend also ends them',
        `refresh -> HTTP ${afterRevoke.status}`);

      // And lifting the suspension restores service for a fresh sign-in.
      fs.writeFileSync(REGISTRY_FILE, originalRegistry);
      await sleep(2500);
      const again = await loginRaw({ persona: 'bob', hint: 'bob@globex.com' });
      report(again.outcome === 'code' ? 'OK' : 'GAP', 'after re-activation a fresh sign-in works again', `outcome=${again.outcome}`);
    });
  } finally {
    fs.writeFileSync(REGISTRY_FILE, originalRegistry);
  }

  const gaps = findings.filter((f) => f.kind === 'GAP');
  console.log(`\n${findings.length} observations: ${findings.filter((f) => f.kind === 'OK').length} OK, ${gaps.length} GAP, ${findings.filter((f) => f.kind === 'INFO').length} INFO`);
  for (const g of gaps) console.log(`  GAP  ${g.name}`);
  process.exit(gaps.length ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(2); });
