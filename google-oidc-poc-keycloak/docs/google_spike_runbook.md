# Real Google spike: runbook

Purpose: replace "our handling of claims" with "Google's actual claim behavior". Everything below the sign-in itself is
already built and dry-run; the sign-ins need your Google accounts in your browser, so they are yours to do.

**What you are testing** (from [architecture_validation.md](architecture_validation.md) §8):

| # | Question | Where it is answered |
|---|---|---|
| 1 | Does a real Workspace sign-in work, with the tenant, provider subject and audience in the token? | Run 1 |
| 2 | Is a personal Gmail refused, and by which layer? | Runs 1 and 2 |
| 3 | What do `hd`, `email` and `sub` look like for aliases and secondary domains? | Run 1 (alias steps) |
| 4 | Does the Google IdP still work with signature validation, issuer check and PKCE on, and is the validation really active? | Runs 1 and 3 |
| 5 | Is a real Workspace domain that is not in the registry refused? | Run 1 (registry step) |

Nothing here touches your real realm (`google-oidc-poc`, port 8280). The spike has its own Keycloak (8380), realm
(`spike-google`), registry (`test-harness/google-spike-registry.json`) and users.

---

## Step 0: a Google OAuth client for the spike (you, in Google Cloud Console)

A personal Gmail can only reach Keycloak if the consent screen is **External**; with **Internal** (your current setup)
Google itself refuses any account outside your organization, which hides the layers we want to test. Pick one:

**Option A (recommended): a separate project, so your real client and consent screen are untouched**
1. Create a new Google Cloud project (any name, e.g. `oidc-spike`).
2. APIs & Services -> OAuth consent screen -> **External**, publishing status **Testing**, add **test users**: your
   Workspace account(s) and a personal Gmail account. Scopes: `openid`, `email`, `profile` only.
3. Credentials -> Create credentials -> OAuth client ID -> **Web application**.
4. Authorized redirect URI (exactly): `http://localhost:8380/realms/spike-google/broker/google/endpoint`
5. Copy the client id and secret.

**Option B: reuse your existing project.** Not recommended: it means switching the consent screen to External/Testing, which
changes who can sign in to the real POC (every user would need to be a listed test user).

In Testing mode Google shows an "unverified app" warning: click **Continue**. Expect that.

## Step 1: give the spike the credentials without pasting them anywhere

Create `google-oidc-poc-keycloak/test-harness/.env.google` in your editor with exactly two lines (the file is git-ignored):

```
GOOGLE_CLIENT_ID=<your client id>
GOOGLE_CLIENT_SECRET=<your client secret>
```

The scripts read it and never print the secret.

## Step 2: bring up the harness and the realm

```powershell
cd google-oidc-poc-keycloak\test-harness
docker compose up -d --build
node scripts\setup-google-spike.mjs
```

It prints the redirect URI to confirm. In this realm the Google IdP has Hosted Domain `*`, `prompt=select_account`,
**signature validation + issuer check + PKCE**, and claim logging on.

## Run 1: the main sign-ins (hardening ON, Hosted Domain `*`)

For each sign-in:

```powershell
node scripts\google-login.mjs            # prints a URL: open it in your browser and sign in
node scripts\observe-google-spike.mjs    # afterwards: what Google sent and which layer accepted or refused
```

| Sign-in | Expected |
|---|---|
| A. Your **Workspace user** (e.g. `yash@yserious.com`) | Browser returns here; claims show `tenant_id=t-yserious`, `idp=google`, `idp_sub` = your 21-digit Google subject, audience `spike-api`. Observer: `iss=https://accounts.google.com`, `hd=yserious.com`, `email_verified=true` |
| B. A **personal Gmail** | Keycloak error page, no callback. Observer: *"REFUSED: Keycloak's own Google check: the ID token has NO hd claim"* (Hosted Domain `*` rejects it before our code runs) |
| C. **Same Workspace user again**, with `--prompt=login` | Works, same `idp_sub` as A, no second Keycloak user |
| D. **Registry step** (a real Workspace domain that is not registered): edit `google-spike-registry.json`, change `"yserious.com"` to `"example.invalid"`, wait 3 seconds, sign in as the Workspace user | 403 page. Observer: `REFUSED by the tenant SPI reason=UNKNOWN_DOMAIN` with the real `hd`. **Restore the file afterwards.** |

### Alias and secondary-domain steps (record what you see; the observer prints it)

1. **User alias** (no extra domain needed): Admin console -> Directory -> Users -> your test user -> User information ->
   Alternate email addresses -> add an alias such as `yash.alias@yserious.com`. At Google's sign-in screen type the *alias*
   address. Record `email`, `hd` and `sub` from the observer: is `email` the alias or the primary address, and is `sub` the same as in A?
2. **Secondary or alias domain** (needs a domain you can verify with DNS): Admin console -> Account -> Domains -> Manage
   domains -> add it (as a *secondary domain* first; try an *alias domain* too if you can). Create a user on it, then
   register the domain for the tenant:
   ```powershell
   $env:REGISTRY_FILE="$PWD\google-spike-registry.json"; $env:KC_URL="http://localhost:8380"; $env:KC_REALM="spike-google"
   node ..\scripts\tenant.mjs add-domain t-yserious <your-secondary-domain>
   ```
   Sign in as that user. Record `hd` versus the email's domain. The observer flags a difference as *"the alias / secondary-domain
   behaviour to record"*. **This single observation decides how the registry must treat secondary domains.**
   Also sign in *before* registering the domain and confirm it is refused (`UNKNOWN_DOMAIN` or `EMAIL_DOMAIN_MISMATCH`).

If you do not own a spare domain, do steps 1 only and say so; step 2 stays open.

## Run 2: the SPI as the only `hd` check (defence in depth)

Keycloak's own Google check rejected the Gmail in Run 1 *before* our code. To prove our layer would catch it on its own
(this matters because Keycloak has had an `hd` bypass in another code path, CVE-2026-18214):

```powershell
$env:GOOGLE_HOSTED_DOMAIN="none"; node scripts\setup-google-spike.mjs
node scripts\google-login.mjs      # sign in with the personal Gmail
node scripts\observe-google-spike.mjs
```

Expected: observer shows the Gmail's real claims with `hd=(ABSENT)` and `REFUSED by the tenant SPI reason=MISSING_HD`,
and no Keycloak user was created. Those claims are also the first look at exactly what Google sends for a consumer account.

## Run 3: prove signature validation is really on

A setting that is never exercised proves nothing. Break the JWKS URL on purpose; sign-in must now **fail**:

```powershell
$env:GOOGLE_JWKS_URL="https://www.googleapis.com/oauth2/v3/certs-does-not-exist"; node scripts\setup-google-spike.mjs
node scripts\google-login.mjs      # sign in as the Workspace user: expect a Keycloak error, no callback
node scripts\observe-google-spike.mjs
```

Then restore (`Remove-Item Env:GOOGLE_JWKS_URL; node scripts\setup-google-spike.mjs`). To compare, `GOOGLE_HARDENING=off` rebuilds the
realm without signature validation, issuer check and PKCE.

---

## Pass criteria

| Spike | Pass |
|---|---|
| Real Workspace login | Sign-in A succeeds; token has `tenant_id`, `idp`, `idp_sub`, audience; `idp_sub` equals the Google subject stored on the same account's user in your real realm (printed by `scripts/migrate-provider-subject.mjs`, or in the admin console under the user's federated identity) |
| Personal Gmail rejection | B refused with no Keycloak user, and Run 2 shows the SPI refusing it independently |
| Stable subject | A and C give the same `idp_sub`; deleting the spike user in the admin console and signing in again gives the same `idp_sub` |
| Hardening | Run 1 works with signature validation, issuer check and PKCE on; Run 3 fails |
| Unregistered domain | D refused with `UNKNOWN_DOMAIN` |
| Alias / secondary | the `hd` / `email` / `sub` values for the alias and secondary-domain users are recorded (there is no pass or fail: the result decides the design) |

## What to send back

The output of `observe-google-spike.mjs` after each run (it contains emails and Google subjects: redact them if you prefer, but keep
the *shape*: which claim names appeared, whether `hd` was absent or present, and `hd` versus the email domain), plus what the
browser showed for every refused account.

## Cleanup

Delete `test-harness/.env.google`; `docker compose down` in `test-harness/`; remove the spike redirect URI (or the whole spike
project) in Google Cloud; delete or rotate the spike client secret.
