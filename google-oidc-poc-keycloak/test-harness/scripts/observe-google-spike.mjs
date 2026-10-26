// Reads the harness Keycloak's log and reports what happened to each REAL Google sign-in against `spike-google`:
// the claims Google actually sent, and which layer accepted or refused the account.
//
// Two layers can refuse an account, and they log differently:
//   1. Keycloak's own Google provider (Hosted Domain check), BEFORE any of our code runs:
//        "Identity token does not contain hosted domain parameter"   (no hd claim: a personal account)
//        "Hosted domain does not match"
//      and signature / issuer failures when the ID-token hardening is on.
//   2. Our tenant-resolver mapper: TENANT_DENIED reason=...   (it also logs GOOGLE_CLAIMS for every login that reaches it)
//
// Usage:  node scripts/observe-google-spike.mjs [--since=6h]
//
// The output contains the account email and Google subject of whoever signed in: it is for you, not for sharing.

import { execSync } from 'node:child_process';

const since = (process.argv.find((a) => a.startsWith('--since=')) ?? '--since=6h').slice(8);
const log = execSync(`docker logs spike-keycloak --since ${since} --timestamps 2>&1`, { encoding: 'utf8', maxBuffer: 100e6 });
const lines = log.split(/\r?\n/);

const events = [];
for (const line of lines) {
  const time = (/^(\S+)\s/.exec(line) ?? [])[1]?.slice(11, 19) ?? '--:--:--';
  let m;
  if ((m = /GOOGLE_CLAIMS idp=(\S+) claims=(\{.*\})/.exec(line))) {
    let claims = {};
    try { claims = JSON.parse(m[2]); } catch { /* keep empty */ }
    events.push({ time, kind: 'claims', claims });
  } else if ((m = /TENANT_RESOLVED tenant=(\S+) hd=(\S+) idp=(\S+) sub=(\S+)/.exec(line))) {
    events.push({ time, kind: 'resolved', tenant: m[1], hd: m[2], sub: m[4] });
  } else if ((m = /TENANT_DENIED reason=(\S+) idp=(\S+) sub=(\S+) detail=(.*)$/.exec(line))) {
    events.push({ time, kind: 'denied', reason: m[1], sub: m[3], detail: m[4] });
  } else if (/TENANT_DENIED reason=(EXISTING_ACCOUNT_NOT_LINKED|USER_\w+)/.test(line)) {
    events.push({ time, kind: 'denied', reason: /reason=(\S+)/.exec(line)[1], detail: line.replace(/^.*TENANT_DENIED /, '') });
  } else if (/Identity token does not contain hosted domain parameter/.test(line)) {
    events.push({ time, kind: 'keycloak-refused', why: 'Keycloak\'s own Google check: the ID token has NO hd claim (personal account)' });
  } else if (/Hosted domain does not match/.test(line)) {
    events.push({ time, kind: 'keycloak-refused', why: 'Keycloak\'s own Google check: hd does not match the configured Hosted Domain' });
  } else if (/(invalid.*signature|signature.*(invalid|failed)|Failed to verify|Invalid token issuer|issuer.*(mismatch|invalid))/i.test(line) && /broker|oidc|idp|identity/i.test(line)) {
    events.push({ time, kind: 'keycloak-refused', why: `ID-token validation failed: ${line.replace(/^\S+\s+/, '').slice(0, 160)}` });
  }
}

if (events.length === 0) {
  console.log(`No Google sign-in activity found in the last ${since}. Run google-login.mjs, sign in, then run this again.`);
  process.exit(0);
}

console.log(`\nspike-google sign-ins in the last ${since} (oldest first)\n`);
const pending = [];
for (const e of events) {
  if (e.kind === 'claims') {
    const c = e.claims;
    pending.push(e);
    const keys = Object.keys(c).sort().join(', ');
    console.log(`${e.time}  GOOGLE CLAIMS RECEIVED`);
    console.log(`          iss=${c.iss}  azp=${c.azp === undefined ? '(absent)' : 'present'}  aud=${JSON.stringify(c.aud)}`);
    console.log(`          sub=${c.sub}  email=${c.email}  email_verified=${JSON.stringify(c.email_verified)}`);
    console.log(`          hd=${c.hd === undefined ? '(ABSENT)' : JSON.stringify(c.hd)}`);
    console.log(`          every claim name Google sent: ${keys}`);
  } else if (e.kind === 'resolved') {
    console.log(`${e.time}  ACCEPTED  tenant=${e.tenant}  hd=${e.hd}  provider-subject=${e.sub}`);
  } else if (e.kind === 'denied') {
    console.log(`${e.time}  REFUSED by the tenant SPI  reason=${e.reason}${e.detail ? `  (${e.detail})` : ''}`);
  } else if (e.kind === 'keycloak-refused') {
    console.log(`${e.time}  REFUSED  ${e.why}`);
  }
}

const claimEvents = events.filter((e) => e.kind === 'claims').map((e) => e.claims);
const withHd = claimEvents.filter((c) => c.hd !== undefined);
const noHd = claimEvents.filter((c) => c.hd === undefined);
const accepted = events.filter((e) => e.kind === 'resolved');
const refusedEarly = events.filter((e) => e.kind === 'keycloak-refused');
const denied = events.filter((e) => e.kind === 'denied');

console.log('\n--- what this shows ---');
console.log(`sign-ins that reached the tenant SPI: ${claimEvents.length}  (with hd: ${withHd.length}, without hd: ${noHd.length})`);
console.log(`accepted: ${accepted.length}   refused by the SPI: ${denied.length}   refused earlier by Keycloak: ${refusedEarly.length}`);
const issuers = [...new Set(claimEvents.map((c) => c.iss))];
if (issuers.length) console.log(`issuer(s) seen: ${issuers.join(', ')}`);
const subjects = claimEvents.map((c) => String(c.sub));
if (subjects.length) console.log(`provider subjects look like: ${subjects.map((s) => `${s.length} chars, ${/^\d+$/.test(s) ? 'numeric' : 'non-numeric'}`).join('; ')}`);
for (const c of withHd) {
  const emailDomain = String(c.email ?? '').split('@')[1];
  console.log(`hd vs email domain: hd=${c.hd}  email domain=${emailDomain}  ${String(c.hd).toLowerCase() === String(emailDomain).toLowerCase() ? '(same)' : '(DIFFERENT: this is the alias / secondary-domain behaviour to record)'}`);
}
console.log('');
