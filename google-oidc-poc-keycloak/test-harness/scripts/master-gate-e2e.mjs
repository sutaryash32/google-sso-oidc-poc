// Proves the MASTER-level tenant gate, and the whole hub-and-spoke chain with a Google-like IdP in master (no stand-in users
// this time): tenant realm -> google-hub -> master -> [master's Google-type IdP = the mock IdP, with personas] -> back.
//
// The mock IdP is registered in master under the alias `mock-google`; setup-tenant.mjs is pointed at it with
// MASTER_IDP_ALIAS / MASTER_HINT, so the script under test builds the real thing: the master attribute importers, the
// broker clients, the tenant gates AND the master gate (union of every tenant's domains, reading raw Google claims).
//
//   docker compose up -d spike-keycloak ; node mock-idp/server.mjs      (leave the mock running; restart it after pulling)
//   node scripts/master-gate-e2e.mjs

import { execFileSync } from 'node:child_process';
import {
  KC, MOCK, api, check, finish, forget, redeem, registerMockInMaster, setup, signIn, usersByEmail,
} from './lib/hub.mjs';

const STARTED = new Date().toISOString();

// ---- setup: a Google-like IdP in master, then two tenants with the script under test ---------------------------------
console.log('--- setup');
for (const realm of ['yserious', 'acme']) await api('DELETE', `/${realm}`);
const created = await registerMockInMaster();
check('mock Google IdP registered in master', created.status === 201, `HTTP ${created.status}`);
const s1 = setup('--id', 'yserious', '--domain', 'yserious.com');
const s2 = setup('--id', 'acme', '--domain', 'acme.com', '--domain', 'acme.co.uk');
check('setup-tenant yserious', s1.ok, s1.ok ? '' : s1.out.slice(-300));
check('setup-tenant acme', s2.ok, s2.ok ? '' : s2.out.slice(-300));
if (!s1.ok || !s2.ok) { console.log(s1.out, s2.out); process.exit(1); }

const masterGate = async () => (await api('GET', `/master/identity-provider/instances/${MOCK}/mappers`)).json
  .find((m) => m.identityProviderMapper === 'hub-tenant-gate-mapper');
let g = await masterGate();
check('master gate bound to the union of all tenants\' domains', g?.config?.['allowed.domains'] === 'acme.co.uk,acme.com,yserious.com', g?.config?.['allowed.domains']);
check('master gate reads raw Google claims', g?.config?.['claim.prefix'] === 'raw' && g?.config?.['gate.name'] === 'master');

// ---- allowed: the chain with a Google-like IdP, master mappers included --------------------------------------------------
console.log('--- allowed');
await forget('ysuser@yserious.com');
const ok = await signIn('yserious', 'ysuser');
console.log('path: ' + ok.path.join(' -> '));
check('yserious persona signs in to yserious', !!ok.code, ok.code ? '' : `stopped (${ok.status}): ${ok.last}`);
if (ok.code) {
  const t = await redeem('yserious', ok);
  check('token: issuer yserious, idp_sub = the persona\'s Google subject', (t.claims.iss ?? '').endsWith('/realms/yserious') && t.claims.idp_sub === 'g-ysuser', t.claims.idp_sub);
  const mu = (await usersByEmail('master', 'ysuser@yserious.com'))[0];
  check('master user created by the master IdP mappers (google_hd, google_sub, google_email_verified)',
    mu?.attributes?.google_hd?.[0] === 'yserious.com' && mu?.attributes?.google_sub?.[0] === 'g-ysuser' && mu?.attributes?.google_email_verified?.[0] === 'true',
    JSON.stringify(mu?.attributes ?? {}));
  check('yserious user created', (await usersByEmail('yserious', 'ysuser@yserious.com')).length === 1);
}
await forget('acmeuser@acme.com');
const acmeOk = await signIn('acme', 'acmeuser');
check('acme persona signs in to acme', !!acmeOk.code, acmeOk.code ? '' : `stopped (${acmeOk.status}): ${acmeOk.last}`);

// ---- denied at MASTER: nothing is created anywhere -------------------------------------------------------------------------
console.log('--- denied at master (no user in master, none in the tenant realm)');
async function deniedAtMaster(label, realm, persona, email) {
  await forget(email);
  const a = await signIn(realm, persona);
  const inMaster = await usersByEmail('master', email), inRealm = await usersByEmail(realm, email);
  check(`${label}: refused (403, no code)`, !a.code && a.status === 403, `status ${a.status}`);
  check(`${label}: refused AT MASTER (the page is master's)`, a.path.some((p) => /\/realms\/master\/broker\/mock-google\/endpoint/.test(p)) && !a.path.some((p) => /\/realms\/yserious\/broker\/google-hub\/endpoint/.test(p) && p.startsWith('200')), a.path.at(-1));
  check(`${label}: no user in master`, inMaster.length === 0, `${inMaster.length}`);
  check(`${label}: no user in ${realm}`, inRealm.length === 0, `${inRealm.length}`);
}
await deniedAtMaster('foreign organisation (globex.com, nobody\'s tenant)', 'yserious', 'bob', 'bob@globex.com');
await deniedAtMaster('foreign organisation unknown-corp.com', 'yserious', 'carol', 'carol@unknown-corp.com');
await deniedAtMaster('consumer account without hd', 'yserious', 'eve', 'eve@gmail.com');
await deniedAtMaster('unverified email at a tenant domain', 'yserious', 'ysunver', 'ysunver@yserious.com');
await deniedAtMaster('look-alike domain acme.com.evil.com', 'yserious', 'trap', 'trap@acme.com.evil.com');

// ---- the residual: a REAL tenant's account sent to the WRONG realm ---------------------------------------------------------
console.log('--- the wrong realm (master cannot know which tenant the person meant)');
await forget('acmeuser@acme.com');
const wrong = await signIn('yserious', 'acmeuser');
check('acme account into the yserious realm: refused by the realm\'s tenant gate (403)', !wrong.code && wrong.status === 403, `status ${wrong.status}`);
check('... no user in yserious', (await usersByEmail('yserious', 'acmeuser@acme.com')).length === 0);
const residue = await usersByEmail('master', 'acmeuser@acme.com');
console.log(`INFO  master keeps a record for a real tenant's account sent to the wrong realm: ${residue.length} user(s) (expected: its own tenant owns that person)`);

// ---- removing a tenant narrows master -----------------------------------------------------------------------------------------
console.log('--- tenant removal');
const rv = setup('--id', 'acme', '--revert');
check('setup-tenant --revert acme', rv.ok, rv.ok ? '' : rv.out.slice(-200));
g = await masterGate();
check('master gate no longer lists acme\'s domains', g?.config?.['allowed.domains'] === 'yserious.com', g?.config?.['allowed.domains']);
await forget('acmeuser@acme.com');
const gone = await signIn('yserious', 'acmeuser');
check('acme account is now refused at master and leaves no record', !gone.code && gone.status === 403 && (await usersByEmail('master', 'acmeuser@acme.com')).length === 0, `status ${gone.status}`);

// ---- control: without the master gate a foreign organisation gets a master record ------------------------------------------
console.log('--- control (master gate removed, then restored)');
const chk = setup('--id', 'yserious', '--check');
check('--check passes (includes the master gate)', chk.ok && /all present/.test(chk.out), chk.ok ? '' : chk.out.slice(-250));
g = await masterGate();
await api('DELETE', `/master/identity-provider/instances/${MOCK}/mappers/${g.id}`);
const bad = setup('--id', 'yserious', '--check');
check('--check reports the missing master gate (exit 1)', !bad.ok && /MISSING.*master gate/.test(bad.out));
await forget('bob@globex.com');
const open = await signIn('yserious', 'bob');
const record = await usersByEmail('master', 'bob@globex.com');
check('CONTROL: without the master gate the foreign account reaches the tenant gate and is still refused there (403)', !open.code && open.status === 403, `status ${open.status}`);
check('CONTROL: ... but master now holds a record for the foreign organisation (what the master gate prevents)', record.length === 1, `${record.length} user(s)`);
await forget('bob@globex.com');
const restore = setup('--id', 'yserious', '--domain', 'yserious.com');
check('setup-tenant restores the master gate', restore.ok && /master gate created/.test(restore.out), restore.ok ? '' : restore.out.slice(-200));
const again = await signIn('yserious', 'bob');
check('after restoring, the foreign account is refused at master again with no record', !again.code && (await usersByEmail('master', 'bob@globex.com')).length === 0);

// ---- the reasons in the log -----------------------------------------------------------------------------------------------------
console.log('--- log');
const log = execFileSync('docker', ['logs', 'spike-keycloak', '--since', STARTED], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 64 * 1024 * 1024 });
for (const [gate, reason] of [['master', 'HD_NOT_ALLOWED'], ['master', 'NO_HD'], ['master', 'EMAIL_NOT_VERIFIED'], ['hub', 'HD_NOT_ALLOWED']]) {
  check(`log shows TENANT_DENIED gate=${gate} reason=${reason}`, new RegExp(`TENANT_DENIED gate=${gate} .*reason=${reason}`).test(log));
}
check('log shows TENANT_ALLOWED gate=master', /TENANT_ALLOWED gate=master/.test(log));

finish();
