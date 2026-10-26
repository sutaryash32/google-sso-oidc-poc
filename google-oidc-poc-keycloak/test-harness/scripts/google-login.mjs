// Receiver for a REAL Google sign-in against the `spike-google` realm.
//
// It prints a URL; you open it in your own browser and sign in with a Google account. This script runs a tiny local
// server on http://localhost:5174 that catches the redirect back, exchanges the code (authorization code + PKCE) and
// prints the claims of the token Keycloak issued: whether the tenant, provider subject and audience came through.
// It never prints a token.
//
// If Keycloak REFUSES the sign-in (a personal Gmail, an unregistered domain, a suspended tenant) you land on a Keycloak
// error page and nothing comes back here; that is the expected outcome. Use `node scripts/observe-google-spike.mjs`
// to see why, from Keycloak's own log.
//
// Usage:  node scripts/google-login.mjs [--hint=user@yserious.com] [--prompt=select_account|login|none] [--wait=300]

import crypto from 'node:crypto';
import http from 'node:http';
import { KC } from './setup-realm.mjs';
import { decode } from './flow.mjs';

const REALM = 'spike-google';
const PORT = 5174;
const REDIRECT = `http://localhost:${PORT}/cb`;
const arg = (name, fallback) => (process.argv.find((a) => a.startsWith(`--${name}=`)) ?? '').slice(name.length + 3) || fallback;

const verifier = crypto.randomBytes(32).toString('base64url');
const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
const state = crypto.randomUUID();
const params = new URLSearchParams({
  client_id: 'spike-app', redirect_uri: REDIRECT, response_type: 'code', scope: 'openid', state, nonce: crypto.randomUUID(),
  code_challenge: challenge, code_challenge_method: 'S256', kc_idp_hint: 'google',
});
if (arg('hint')) params.set('login_hint', arg('hint'));
if (arg('prompt')) params.set('prompt', arg('prompt'));
const loginUrl = `${KC}/realms/${REALM}/protocol/openid-connect/auth?${params}`;
const waitSeconds = Number(arg('wait', '300'));

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, REDIRECT);
  if (url.pathname !== '/cb') { res.writeHead(404).end(); return; }
  res.writeHead(200, { 'content-type': 'text/plain' });
  try {
    if (url.searchParams.get('error')) throw new Error(`Keycloak returned error=${url.searchParams.get('error')}`);
    if (url.searchParams.get('state') !== state) throw new Error('state mismatch');
    const tokenRes = await fetch(`${KC}/realms/${REALM}/protocol/openid-connect/token`, {
      method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'authorization_code', client_id: 'spike-app', code: url.searchParams.get('code'),
        redirect_uri: REDIRECT, code_verifier: verifier }),
    });
    const json = await tokenRes.json();
    if (!tokenRes.ok) throw new Error(`token endpoint refused: ${JSON.stringify(json)}`);
    const c = decode(json.access_token);
    const summary = {
      iss: c.iss, aud: c.aud, email: c.email, tenant_id: c.tenant_id, tenant_domain: c.tenant_domain,
      idp: c.idp, idp_sub: c.idp_sub, keycloak_sub: c.sub,
    };
    console.log('\nSIGN-IN SUCCEEDED. Token claims:');
    for (const [k, v] of Object.entries(summary)) console.log(`  ${k.padEnd(14)} ${JSON.stringify(v)}`);
    res.end('Signed in. You can close this tab and return to the terminal.');
  } catch (e) {
    console.log(`\nSIGN-IN DID NOT COMPLETE: ${e.message}`);
    res.end('Sign-in did not complete. See the terminal.');
  }
  server.close();
  process.exit(0);
});

server.listen(PORT, 'localhost', () => {
  console.log(`Listening on ${REDIRECT} (waiting up to ${waitSeconds}s).\n`);
  console.log('Open this URL in your browser and sign in with Google:\n');
  console.log(loginUrl + '\n');
});
setTimeout(() => {
  console.log('\nNo callback received. If Keycloak showed an error page that is the expected result for a refused account;');
  console.log('run `node scripts/observe-google-spike.mjs` to see the reason.');
  process.exit(0);
}, waitSeconds * 1000);
