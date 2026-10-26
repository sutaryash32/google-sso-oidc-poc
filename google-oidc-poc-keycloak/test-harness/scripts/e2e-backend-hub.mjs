// Backend validation per tenant realm, end to end: the REAL backend (built jar, started by this script) against two real
// tenant realms (yserious, acme) on the harness Keycloak, with tokens obtained through the full chain
//   tenant realm -> google-hub -> master -> mock Google IdP.
// The registry gives each tenant its own issuer. What is proved: each realm's tokens are accepted for its own tenant only,
// a realm that writes another tenant's id into its tokens is refused, an issuer nobody registered is never trusted, removing
// a tenant from the registry cuts its realm off at once, and tenant data stays isolated.
//
//   docker compose up -d spike-keycloak spike-db ; node mock-idp/server.mjs      (mock IdP left running)
//   node scripts/e2e-backend-hub.mjs        (builds the backend jar first; needs Maven and Java on the PATH)

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execSync, spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  KC, api, check, finish, forget, redeem, registerMockInMaster, setup, signIn,
} from './lib/hub.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BACKEND_DIR = path.resolve(HERE, '../../../google-oidc-poc-backend');
const PORT = 8196;
const BACKEND = `http://localhost:${PORT}`;
const REGISTRY = path.join(os.tmpdir(), 'hub-backend-registry.json');

const tenant = (id, name, domain, realm) => ({
  tenantId: id, name, status: 'active', ssoEnabled: true, domains: [domain], issuer: `${KC}/realms/${realm}`,
});
const writeRegistry = (tenants) => fs.writeFileSync(REGISTRY, JSON.stringify({ tenants }, null, 2));

async function call(p, { token, method = 'GET', body } = {}) {
  const res = await fetch(`${BACKEND}${p}`, {
    method,
    headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), ...(body !== undefined ? { 'content-type': 'application/json' } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let json; try { json = JSON.parse(text); } catch { json = undefined; }
  return { status: res.status, json, text };
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const tokenFor = async (realm, persona, email) => {
  await forget(email);
  const attempt = await signIn(realm, persona);
  if (!attempt.code) throw new Error(`sign-in as ${persona} into ${realm} failed (${attempt.status}): ${attempt.last}`);
  return redeem(realm, attempt);
};

// ---- keycloak side -----------------------------------------------------------------------------------------------------
console.log('--- setup');
for (const realm of ['yserious', 'acme', 'rogue']) await api('DELETE', `/${realm}`);
check('mock Google IdP registered in master', (await registerMockInMaster()).status === 201);
check('setup-tenant yserious', setup('--id', 'yserious', '--domain', 'yserious.com').ok);
check('setup-tenant acme', setup('--id', 'acme', '--domain', 'acme.com').ok);
// A third realm exists in Keycloak but is NOT in the backend's registry: an issuer nobody registered.
check('setup-tenant rogue (a realm the backend registry will not list)', setup('--id', 'rogue', '--domain', 'acme.com', '--tenant-id', 't-rogue').ok);

// ---- backend -----------------------------------------------------------------------------------------------------------
console.log('--- backend');
writeRegistry([tenant('t-yserious', 'Yserious', 'yserious.com', 'yserious'), tenant('t-acme', 'Acme', 'acme.com', 'acme')]);
execSync('mvn -o -q -DskipTests package', { cwd: BACKEND_DIR, stdio: 'inherit' });
const jar = fs.readdirSync(path.join(BACKEND_DIR, 'target')).find((f) => f.endsWith('.jar') && !f.endsWith('.original'));
const logFile = path.join(os.tmpdir(), 'hub-backend.log');
const child = spawn('java', ['-Duser.timezone=UTC', '-jar', path.join(BACKEND_DIR, 'target', jar)], {
  env: { ...process.env, SPRING_DOCKER_COMPOSE_ENABLED: 'false', SERVER_PORT: String(PORT), TENANT_AUDIENCE: 'oidc-poc-api',
    TENANT_REGISTRY_FILE: REGISTRY, TENANT_DB_URL: 'jdbc:postgresql://localhost:5434/spike', TENANT_ISSUER: '', TENANT_JWK_SET_URI: '' },
  stdio: ['ignore', fs.openSync(logFile, 'w'), fs.openSync(logFile, 'a')],
});
// child.kill() alone left the JVM listening on Windows; kill the whole process tree there.
function stopBackend() {
  try {
    if (process.platform === 'win32') execSync(`taskkill /PID ${child.pid} /T /F`, { stdio: 'ignore' });
    else child.kill('SIGKILL');
  } catch { /* already gone */ }
}
let up = false;
for (let i = 0; i < 60 && !up; i++) { await sleep(2000); try { up = (await call('/api/public')).status === 200; } catch { /* not yet */ } }
check('backend started (registry issuers only, no legacy issuer)', up, up ? '' : fs.readFileSync(logFile, 'utf8').slice(-400));
if (!up) { stopBackend(); process.exit(1); }

try {
  // ---- tokens from two realms ---------------------------------------------------------------------------------------------
  console.log('--- each realm for its own tenant');
  const ys = await tokenFor('yserious', 'ysuser', 'ysuser@yserious.com');
  const ac = await tokenFor('acme', 'acmeuser', 'acmeuser@acme.com');
  check('tokens carry their own realm as issuer', ys.claims.iss === `${KC}/realms/yserious` && ac.claims.iss === `${KC}/realms/acme`);

  const meYs = await call('/api/tenant/me', { token: ys.accessToken });
  const meAc = await call('/api/tenant/me', { token: ac.accessToken });
  check('yserious token: 200, tenant t-yserious', meYs.status === 200 && meYs.json?.tenantId === 't-yserious', `${meYs.status} ${meYs.text.slice(0, 80)}`);
  check('acme token: 200, tenant t-acme', meAc.status === 200 && meAc.json?.tenantId === 't-acme', `${meAc.status} ${meAc.text.slice(0, 80)}`);
  check('no token: 401', (await call('/api/tenant/me')).status === 401);
  check('garbage token: 401', (await call('/api/tenant/me', { token: 'not.a.jwt' })).status === 401);

  // ---- tenant data stays isolated -----------------------------------------------------------------------------------------
  console.log('--- isolation');
  const doc = await call('/api/documents', { token: ys.accessToken, method: 'POST', body: { title: 'ys-secret', body: 'only yserious' } });
  check('yserious creates a document', doc.status === 201, `${doc.status}`);
  const acList = await call('/api/documents', { token: ac.accessToken });
  check('acme cannot see it', acList.status === 200 && !JSON.stringify(acList.json).includes('ys-secret'), `${acList.status}`);
  const ysList = await call('/api/documents', { token: ys.accessToken });
  check('yserious sees its own', JSON.stringify(ysList.json).includes('ys-secret'));
  check('acme asking for the yserious tenant path gets nothing', (await call('/api/tenants/t-yserious/documents', { token: ac.accessToken })).status === 404);

  // ---- a realm that lies about its tenant ---------------------------------------------------------------------------------
  console.log('--- a realm that claims another tenant');
  const acmeClient = (await api('GET', '/acme/clients?clientId=google-oidc-poc-frontend')).json[0];
  const tenantIdMapper = acmeClient.protocolMappers.find((m) => m.name === 'tenant_id');
  const tenantDomainMapper = acmeClient.protocolMappers.find((m) => m.name === 'tenant_domain');
  await api('PUT', `/acme/clients/${acmeClient.id}/protocol-mappers/models/${tenantIdMapper.id}`,
    { ...tenantIdMapper, config: { ...tenantIdMapper.config, 'claim.value': 't-yserious' } });
  await api('PUT', `/acme/clients/${acmeClient.id}/protocol-mappers/models/${tenantDomainMapper.id}`,
    { ...tenantDomainMapper, config: { ...tenantDomainMapper.config, 'claim.value': 'yserious.com' } });
  const forged = await tokenFor('acme', 'acmeuser', 'acmeuser@acme.com');
  check('the forged token really says tenant t-yserious / yserious.com, issued by acme',
    forged.claims.tenant_id === 't-yserious' && forged.claims.tenant_domain === 'yserious.com' && forged.claims.iss === `${KC}/realms/acme`);
  const forgedMe = await call('/api/tenant/me', { token: forged.accessToken });
  check('backend refuses it (403 issuer_mismatch), though signature, issuer, audience and claims are all valid',
    forgedMe.status === 403 && forgedMe.text.includes('issuer_mismatch'), `${forgedMe.status} ${forgedMe.text.slice(0, 80)}`);
  const forgedDocs = await call('/api/documents', { token: forged.accessToken });
  check('... and it cannot read yserious documents', forgedDocs.status === 403 && !forgedDocs.text.includes('ys-secret'), `${forgedDocs.status}`);

  // ---- an issuer nobody registered ----------------------------------------------------------------------------------------
  console.log('--- an issuer that is not in the registry');
  const rogue = await tokenFor('rogue', 'acmeuser', 'acmeuser@acme.com');
  check('a rogue realm\'s token is a fully valid Keycloak token', !!rogue.accessToken && rogue.claims.iss === `${KC}/realms/rogue`);
  const rogueMe = await call('/api/tenant/me', { token: rogue.accessToken });
  check('backend rejects it (401): the issuer is not trusted', rogueMe.status === 401, `${rogueMe.status}`);

  // ---- removing a tenant --------------------------------------------------------------------------------------------------
  console.log('--- registry changes take effect at once');
  writeRegistry([tenant('t-yserious', 'Yserious', 'yserious.com', 'yserious')]);
  await sleep(1500);
  const acmeGone = await call('/api/tenant/me', { token: ac.accessToken });
  check('acme removed from the registry: its still-valid token is rejected (401)', acmeGone.status === 401, `${acmeGone.status}`);
  check('yserious unaffected', (await call('/api/tenant/me', { token: ys.accessToken })).status === 200);
  const suspended = tenant('t-yserious', 'Yserious', 'yserious.com', 'yserious'); suspended.status = 'suspended';
  writeRegistry([suspended]);
  await sleep(1500);
  const ysSuspended = await call('/api/tenant/me', { token: ys.accessToken });
  check('yserious suspended: 403 tenant_suspended', ysSuspended.status === 403 && ysSuspended.text.includes('tenant_suspended'), `${ysSuspended.status}`);
} finally {
  stopBackend();
}
finish();
