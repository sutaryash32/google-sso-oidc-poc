// Harness bootstrap shared by the hub-and-spoke e2e suites that use a Google-like IdP in master (the mock IdP, with personas):
// admin API access, running scripts/setup-tenant.mjs against the harness, and a browserless sign-in through
// tenant realm -> google-hub -> master -> mock IdP -> back.

import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { Jar, decode } from './browser.mjs';

export const KC = process.env.KC_URL ?? 'http://localhost:8380';
export const REDIRECT = 'http://localhost:5173/cb';
export const MOCK = 'mock-google';
export const SETUP = new URL('../../../scripts/setup-tenant.mjs', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');

export const results = [];
export const check = (name, ok, detail = '') => { results.push(ok); console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? `  (${detail})` : ''}`); };
export function finish() {
  const failed = results.filter((r) => !r).length;
  console.log(`\n${results.length - failed}/${results.length} checks passed`);
  process.exit(failed ? 1 : 0);
}

const admin = (await (await fetch(`${KC}/realms/master/protocol/openid-connect/token`, {
  method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({ grant_type: 'password', client_id: 'admin-cli', username: 'admin', password: 'admin' }),
})).json()).access_token;

export const api = async (method, path, body) => {
  const res = await fetch(`${KC}/admin/realms${path}`, { method, headers: { authorization: `Bearer ${admin}`, 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await res.text();
  return { status: res.status, json: text ? JSON.parse(text) : null };
};

/** Runs scripts/setup-tenant.mjs against the harness, with the mock IdP as master's Google IdP. */
export const setup = (...args) => {
  try {
    return { ok: true, out: execFileSync('node', [SETUP, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, KC_URL: KC, KC_INTERNAL_URL: 'http://localhost:8080', MASTER_IDP_ALIAS: MOCK, MASTER_HINT: MOCK,
        GOOGLE_CLIENT_ID: 'x', GOOGLE_CLIENT_SECRET: 'x' } }) };
  } catch (e) { return { ok: false, out: `${e.stdout ?? ''}${e.stderr ?? ''}` }; }
};

export const usersByEmail = async (realm, email) => {
  const res = await api('GET', `/${realm}/users?email=${encodeURIComponent(email)}&exact=true`);
  return Array.isArray(res.json) ? res.json : [];      // a realm that no longer exists has no users
};
export const forget = async (email, realms = ['master', 'yserious', 'acme']) => {
  for (const realm of realms) for (const u of await usersByEmail(realm, email)) await api('DELETE', `/${realm}/users/${u.id}`);
};

/** Registers the mock IdP in master as a Google-type IdP (alias mock-google), replacing any previous one. */
export async function registerMockInMaster() {
  await api('DELETE', `/master/identity-provider/instances/${MOCK}`);
  return api('POST', '/master/identity-provider/instances', {
    alias: MOCK, providerId: 'oidc', enabled: true, trustEmail: false, firstBrokerLoginFlowAlias: 'first broker login',
    config: { clientId: 'spike-kc', clientSecret: 'spike-secret', clientAuthMethod: 'client_secret_post',
      authorizationUrl: 'http://localhost:9100/authorize', tokenUrl: 'http://host.docker.internal:9100/token',
      jwksUrl: 'http://host.docker.internal:9100/jwks', useJwksUrl: 'true', validateSignature: 'true', issuer: 'http://localhost:9100',
      defaultScope: 'openid email profile', disableUserInfo: 'true', syncMode: 'IMPORT' },
  });
}

/** Sign in to `realm` through google-hub and master, as a mock persona. Resolves { code, status, path, verifier, last }. */
export async function signIn(realm, persona) {
  const jar = new Jar();
  const verifier = crypto.randomBytes(32).toString('base64url');
  const params = new URLSearchParams({
    client_id: 'google-oidc-poc-frontend', redirect_uri: REDIRECT, response_type: 'code', scope: 'openid',
    state: crypto.randomUUID(), nonce: crypto.randomUUID(), kc_idp_hint: 'google-hub',
    code_challenge: crypto.createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256',
  });
  let url = `${KC}/realms/${realm}/protocol/openid-connect/auth?${params}`;
  const path = [];
  let status = 0, last = '';
  for (let hop = 0; hop < 25; hop++) {
    const headers = { cookie: jar.header(url) };
    if (new URL(url).port === '9100') headers['x-persona'] = persona;
    const res = await fetch(url, { redirect: 'manual', headers });
    jar.store(url, res);
    status = res.status;
    path.push(`${res.status} ${new URL(url).host}${new URL(url).pathname}`);
    if (res.status >= 300 && res.status < 400) {
      const next = new URL(res.headers.get('location'), url).toString();
      if (next.startsWith(REDIRECT)) return { code: new URL(next).searchParams.get('code'), status, path, verifier, last };
      url = next; continue;
    }
    last = (await res.text()).replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 140);
    break;
  }
  return { code: null, status, path, verifier, last };
}

/** Redeems the authorization code of a successful signIn. Resolves { ok, accessToken, claims, error }. */
export async function redeem(realm, attempt) {
  const res = await fetch(`${KC}/realms/${realm}/protocol/openid-connect/token`, {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'authorization_code', client_id: 'google-oidc-poc-frontend', code: attempt.code,
      redirect_uri: REDIRECT, code_verifier: attempt.verifier }) });
  const json = await res.json();
  return { ok: res.ok, accessToken: json.access_token, claims: res.ok ? decode(json.access_token) : {}, error: json.error_description };
}
