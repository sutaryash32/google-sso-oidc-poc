// Browser-flow helper shared by the backend e2e: authorization code + PKCE against the spike
// Keycloak, brokered through the mock IdP with a chosen persona. Returns tokens for a given client.

import crypto from 'node:crypto';
import { KC, REALM } from './setup-realm.mjs';

const REDIRECT = 'http://localhost:5174/cb';

export class Jar {
  #c = new Map();
  store(url, res) {
    const origin = new URL(url).origin;
    for (const sc of res.headers.getSetCookie()) {
      const [pair] = sc.split(';');
      const i = pair.indexOf('=');
      const key = `${origin}|${pair.slice(0, i).trim()}`;
      const value = pair.slice(i + 1);
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

export const decode = (jwt) => JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString());

/** Full login as `persona` for `clientId`. Resolves to { accessToken, claims } or throws. */
export async function tokenFor({ persona, clientId = 'spike-app', hint }) {
  const jar = new Jar();
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  const params = new URLSearchParams({
    client_id: clientId, redirect_uri: REDIRECT, response_type: 'code', scope: 'openid',
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
        const code = new URL(next).searchParams.get('code');
        if (!code) throw new Error(`login for ${persona}/${clientId} returned no code: ${next}`);
        const tokenRes = await fetch(`${KC}/realms/${REALM}/protocol/openid-connect/token`, {
          method: 'POST',
          headers: { 'content-type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type: 'authorization_code', client_id: clientId, code,
            redirect_uri: REDIRECT, code_verifier: verifier,
          }),
        });
        const json = await tokenRes.json();
        if (!tokenRes.ok) throw new Error(`token redeem failed: ${JSON.stringify(json)}`);
        return { accessToken: json.access_token, claims: decode(json.access_token) };
      }
      url = next;
      continue;
    }
    throw new Error(`login for ${persona}/${clientId} ended on HTTP ${res.status} (denied?)`);
  }
  throw new Error('too many redirects');
}
