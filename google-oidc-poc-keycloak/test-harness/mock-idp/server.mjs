// Minimal mock OIDC provider that stands in for Google in the spike.
// It issues RS256 ID tokens whose claims (hd, email, email_verified, ...) are chosen by
// the test harness via the `x-persona` header on /authorize. No dependencies.
//
// Usage: node server.mjs   (listens on 0.0.0.0:9100)

import http from 'node:http';
import crypto from 'node:crypto';

const PORT = 9100;
// Issuer is what the BROWSER-facing config uses; Keycloak (in Docker) reaches token/jwks via host.docker.internal.
const ISSUER = 'http://localhost:9100';

const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const KID = 'mock-' + crypto.randomBytes(4).toString('hex');
const jwk = { ...publicKey.export({ format: 'jwk' }), kid: KID, alg: 'RS256', use: 'sig' };

const person = (sub, email, extra = {}) => ({
  sub, email, email_verified: true,
  given_name: email.split('@')[0], family_name: 'Tester', name: `${email.split('@')[0]} Tester`,
  ...extra,
});

// persona id -> claims. `hd` is deliberately absent for the consumer-Gmail persona.
export const PERSONAS = {
  alice:    person('g-alice',    'alice@acme.com',            { hd: 'acme.com' }),
  bob:      person('g-bob',      'bob@globex.com',            { hd: 'globex.com' }),
  upper:    person('g-upper',    'Upper@ACME.com',            { hd: 'ACME.COM' }),
  carol:    person('g-carol',    'carol@unknown-corp.com',    { hd: 'unknown-corp.com' }),
  eve:      person('g-eve',      'eve@gmail.com'),            // consumer account: no hd
  dave:     person('g-dave',     'dave@initech.com',          { hd: 'initech.com' }),
  hank:     person('g-hank',     'hank@hooli.com',            { hd: 'hooli.com' }),
  frank:    person('g-frank',    'frank@acme.com',            { hd: 'acme.com', email_verified: false }),
  zed:      person('g-zed',      'zed@globex.com',            { hd: 'globex.com' }),
  mallory:  person('g-mallory',  'mallory@globex.com',        { hd: 'acme.com' }),   // email domain != hd tenant
  conflict: person('g-conflict', 'conflict@acme.com',         { hd: 'acme.com' }),
  dupuser:  person('g-dupuser',  'dupuser@dup.com',           { hd: 'dup.com' }),
  trap:     person('g-trap',     'trap@acme.com.evil.com',    { hd: 'acme.com.evil.com' }),

  // --- personas for e2e-attacks.mjs (identity-lifecycle and alias cases) ---
  alice2:       person('g-alice-2', 'alice@acme.com',        { hd: 'acme.com' }),      // alice deleted and re-created: NEW sub, same email
  aliceRenamed: person('g-alice',   'alice.new@acme.com',    { hd: 'acme.com' }),      // same person (same sub), email renamed
  sam:          person('g-sam',     'sam@acme.co.uk',        { hd: 'acme.com' }),      // primary email on a secondary domain of the tenant
  sec:          person('g-sec',     'pat@acme.com',          { hd: 'acme.co.uk' }),    // hd reports the tenant's secondary domain
  unmanaged:    person('g-unmanaged', 'ceo@acme.com'),                                 // consumer Google account registered with a corporate address: verified email, NO hd
};

// --- personas for hub-and-spoke-master-gate-e2e.mjs (tenant yserious.com, plus foreign organisations) ---
Object.assign(PERSONAS, {
  ysuser:   person('g-ysuser',   'ysuser@yserious.com',   { hd: 'yserious.com' }),
  ysunver:  person('g-ysunver',  'ysunver@yserious.com',  { hd: 'yserious.com', email_verified: false }),
  acmeuser: person('g-acmeuser', 'acmeuser@acme.com',     { hd: 'acme.com' }),
});

const codes = new Map(); // code -> { persona, nonce, clientId, redirectUri }

const b64 = (buf) => Buffer.from(buf).toString('base64url');

function signIdToken(claims) {
  const header = { alg: 'RS256', typ: 'JWT', kid: KID };
  const input = `${b64(JSON.stringify(header))}.${b64(JSON.stringify(claims))}`;
  const sig = crypto.sign('RSA-SHA256', Buffer.from(input), privateKey);
  return `${input}.${b64(sig)}`;
}

function readBody(req) {
  return new Promise((resolve) => {
    let data = '';
    req.on('data', (c) => (data += c));
    req.on('end', () => resolve(data));
  });
}

function json(res, status, body) {
  res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
  res.end(JSON.stringify(body));
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, ISSUER);

  if (url.pathname === '/.well-known/openid-configuration') {
    return json(res, 200, {
      issuer: ISSUER,
      authorization_endpoint: `${ISSUER}/authorize`,
      token_endpoint: `http://host.docker.internal:${PORT}/token`,
      jwks_uri: `http://host.docker.internal:${PORT}/jwks`,
      response_types_supported: ['code'],
      id_token_signing_alg_values_supported: ['RS256'],
      subject_types_supported: ['public'],
    });
  }

  if (url.pathname === '/jwks') {
    return json(res, 200, { keys: [jwk] });
  }

  if (url.pathname === '/authorize') {
    const personaId = req.headers['x-persona'];
    const persona = PERSONAS[personaId];
    if (!persona) {
      return json(res, 400, { error: 'unknown_persona', persona: personaId ?? null });
    }
    const redirectUri = url.searchParams.get('redirect_uri');
    const code = crypto.randomBytes(16).toString('hex');
    codes.set(code, {
      persona,
      nonce: url.searchParams.get('nonce'),
      clientId: url.searchParams.get('client_id'),
    });
    const back = new URL(redirectUri);
    back.searchParams.set('code', code);
    back.searchParams.set('state', url.searchParams.get('state') ?? '');
    res.writeHead(302, { location: back.toString() });
    return res.end();
  }

  if (url.pathname === '/token' && req.method === 'POST') {
    const form = new URLSearchParams(await readBody(req));
    const entry = codes.get(form.get('code'));
    codes.delete(form.get('code')); // single use
    if (!entry) {
      return json(res, 400, { error: 'invalid_grant' });
    }
    const now = Math.floor(Date.now() / 1000);
    const claims = {
      iss: ISSUER,
      aud: entry.clientId,
      iat: now,
      exp: now + 300,
      nonce: entry.nonce ?? undefined,
      ...entry.persona,
    };
    return json(res, 200, {
      access_token: crypto.randomBytes(16).toString('hex'),
      token_type: 'Bearer',
      expires_in: 300,
      id_token: signIdToken(claims),
    });
  }

  json(res, 404, { error: 'not_found' });
});

server.listen(PORT, '0.0.0.0', () => console.log(`mock-idp listening on :${PORT} (issuer ${ISSUER})`));
