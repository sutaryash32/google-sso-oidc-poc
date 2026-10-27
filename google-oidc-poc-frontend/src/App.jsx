import { useEffect, useState } from 'react';
import keycloak, { idpHint, tenant, tenantSelectable, switchTenant, forgetTenant } from './keycloak';
import './App.css';

const BACKEND_URL = 'http://localhost:8095';

// Google's four brand colours, used for avatars so each person / group gets a stable one.
const GOOGLE_COLORS = ['#4285f4', '#ea4335', '#f9ab00', '#34a853'];
const colorFor = (text) => GOOGLE_COLORS[[...String(text || '?')].reduce((n, ch) => n + ch.charCodeAt(0), 0) % 4];

function GoogleG({ size = 20 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 48 48" aria-hidden="true" focusable="false">
      <path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z" />
      <path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z" />
      <path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z" />
      <path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z" />
    </svg>
  );
}

/** Ask the backend which realm an organization's domain signs in to, then switch to it. */
async function chooseOrganization(domainInput) {
  const domain = domainInput.trim().toLowerCase().replace(/^.*@/, '');
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(domain)) {
    throw new Error('Enter your organization\'s domain, for example acme.com.');
  }
  const res = await fetch(`${BACKEND_URL}/api/public/tenant?domain=${encodeURIComponent(domain)}`);
  if (!res.ok) throw new Error(`${domain} is not a registered organization.`);
  const { realm } = await res.json();
  switchTenant(realm, domain);
}

// keycloak-js throws if init() runs twice, and React StrictMode double-invokes
// effects in dev — so share one init promise across mounts.
let keycloakInit;
function initKeycloak() {
  if (!keycloakInit) {
    keycloakInit = keycloak.init({ onLoad: 'check-sso', pkceMethod: 'S256' });
  }
  return keycloakInit;
}

export default function App() {
  const [authenticated, setAuthenticated] = useState(false);
  const [userEmail, setUserEmail] = useState(null);
  const [meInfo, setMeInfo] = useState(null);
  const [groups, setGroups] = useState(null);
  const [error, setError] = useState(null);
  const [groupsError, setGroupsError] = useState(null);
  const [tenantInfo, setTenantInfo] = useState(null);
  const [tenantError, setTenantError] = useState(null);
  const [orgInput, setOrgInput] = useState('');
  const [orgError, setOrgError] = useState(null);
  const [orgBusy, setOrgBusy] = useState(false);

  useEffect(() => {
    initKeycloak()
      .then((auth) => {
        setAuthenticated(auth);
        if (auth) {
          setUserEmail(keycloak.tokenParsed?.email);
        } else {
          // Just switched organization: go straight to its sign-in.
          let auto = false;
          try {
            auto = sessionStorage.getItem('autoLogin') === '1';
            sessionStorage.removeItem('autoLogin');
          } catch {
            /* storage unavailable */
          }
          if (auto) keycloak.login({ idpHint });
        }
      })
      .catch((err) => {
        console.error('Keycloak init error:', err);
        setError(String(err));
      });
  }, []);

  useEffect(() => {
    if (!userEmail) return;

    fetch(`${BACKEND_URL}/api/me`, {
      headers: { Authorization: `Bearer ${keycloak.token}` },
    })
      .then((res) => {
        if (!res.ok) throw new Error(`/api/me returned ${res.status}`);
        return res.json();
      })
      .then(setMeInfo)
      .catch((err) => {
        console.error('/api/me fetch error:', err);
        setError(String(err));
      });

    // The tenant the backend resolved from the token (never chosen by the browser).
    fetch(`${BACKEND_URL}/api/tenant/me`, {
      headers: { Authorization: `Bearer ${keycloak.token}` },
    })
      .then(async (res) => {
        if (!res.ok) {
          const body = await res.json().catch(() => ({}));
          throw new Error(body.error ? `${body.error} (${res.status})` : `tenant endpoint returned ${res.status}`);
        }
        return res.json();
      })
      .then(setTenantInfo)
      .catch((err) => {
        console.error('/tenant/me fetch error:', err);
        setTenantError(String(err.message ?? err));
      });

    fetch(`${BACKEND_URL}/api/users/${encodeURIComponent(userEmail)}/groups`, {
      headers: { Authorization: `Bearer ${keycloak.token}` },
    })
      .then((res) => {
        if (!res.ok) throw new Error(`groups endpoint returned ${res.status}`);
        return res.json();
      })
      .then((data) => setGroups(data.groups))
      .catch((err) => {
        console.error('/groups fetch error:', err);
        setGroupsError(String(err));
      });
  }, [userEmail]);

  if (error) {
    return (
      <div className="page">
        <div className="stack">
          <div className="card">
            <div className="notice notice-error">Error: {error}</div>
            {/* A 401 usually means the session predates a change to the tenant claims; signing in again fixes it. */}
            {error.includes('401') && (
              <p className="muted" style={{ marginTop: 12 }}>
                Your session may be outdated. Sign out and sign in again to get a token with your tenant.
              </p>
            )}
            <div style={{ marginTop: 12 }}>
              <button className="btn" onClick={() => keycloak.logout()}>Sign out and try again</button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (!authenticated) {
    // One step. A remembered (or fixed) organization gets one button; otherwise the user says who they are and continues.
    const known = tenant.chosen || !tenantSelectable;
    const orgName = tenant.domain || tenant.realm;
    return (
      <div className="page">
        <div className="stack">
          <div className="card login">
            <div className="login-logo"><GoogleG size={44} /></div>
            <h1>Sign in</h1>
            {known ? (
              <>
                <p className="login-sub">to <strong>{orgName}</strong> with your Google Workspace account</p>
                <button className="btn btn-google btn-wide" onClick={() => keycloak.login({ idpHint })}>
                  <GoogleG size={18} />
                  <span>Continue with Google</span>
                </button>
                {tenantSelectable && (
                  <button className="link" type="button" onClick={forgetTenant}>Not {orgName}? Use a different organization</button>
                )}
                {!tenantSelectable && (
                  <p className="login-note">The organization is fixed by this app's configuration.</p>
                )}
              </>
            ) : (
              <form
                className="login-form"
                onSubmit={(e) => {
                  e.preventDefault();
                  setOrgError(null);
                  setOrgBusy(true);
                  chooseOrganization(orgInput).catch((err) => {
                    setOrgError(err.message);
                    setOrgBusy(false);
                  });
                }}
              >
                <p className="login-sub">Use your organization's Google Workspace account</p>
                <label htmlFor="org">Work email or organization domain</label>
                <input
                  id="org"
                  className="field"
                  type="text"
                  autoFocus
                  autoComplete="email"
                  value={orgInput}
                  placeholder="you@acme.com or acme.com"
                  onChange={(e) => setOrgInput(e.target.value)}
                />
                {orgError && <div className="notice notice-error">{orgError}</div>}
                <button className="btn btn-primary btn-wide" type="submit" disabled={orgBusy || !orgInput.trim()}>
                  {orgBusy ? 'Checking…' : 'Continue'}
                </button>
              </form>
            )}
          </div>
        </div>
      </div>
    );
  }

  const displayName = meInfo?.name || keycloak.tokenParsed?.name || userEmail;
  const initial = (displayName || '?').trim().charAt(0).toUpperCase();
  const roles = meInfo?.roles || [];

  return (
    <div className="page">
      <div className="stack">
        <div className="card profile">
          <div className="avatar" aria-hidden="true" style={{ background: colorFor(displayName) }}>{initial}</div>
          <div className="profile-text">
            <div className="profile-name">{displayName}</div>
            <div className="profile-email">{userEmail}</div>
          </div>
          <button className="btn" onClick={() => keycloak.logout()}>Logout</button>
        </div>

        <div className="card">
          <h3>Identity</h3>
          {meInfo === null && <div className="skeleton" />}
          {meInfo && (
            <dl className="kv">
              <dt>Name</dt>
              <dd>{meInfo.name}</dd>
              <dt>Username</dt>
              <dd>{meInfo.preferredUsername}</dd>
              <dt>Tenant</dt>
              <dd>
                {tenantInfo && (
                  <>{tenantInfo.tenantDomain} <span className="empty">({tenantInfo.tenantId})</span></>
                )}
                {!tenantInfo && !tenantError && <span className="empty">loading…</span>}
                {tenantError && <span style={{ color: 'var(--danger)' }}>{tenantError}</span>}
              </dd>
              <dt>Identity provider</dt>
              <dd>{meInfo.identityProvider || <span className="empty">not provided</span>}</dd>
              <dt>Roles</dt>
              <dd>
                {roles.length === 0 && <span className="empty">none</span>}
                <div className="chips">
                  {roles.map((r) => (
                    <span className="chip" key={r}>{r}</span>
                  ))}
                </div>
              </dd>
            </dl>
          )}
        </div>

        <div className="card">
          <h3>Google Groups</h3>
          {groupsError && (
            <div className="notice notice-error">Could not load groups: {groupsError}</div>
          )}
          {groups === null && !groupsError && <div className="skeleton" />}
          {groups && groups.length === 0 && (
            <p className="muted">No groups found for this user.</p>
          )}
          {groups && groups.length > 0 && (
            <ul className="list">
              {groups.map((g) => (
                <li key={g.id}>
                  <span className="g-avatar" aria-hidden="true" style={{ background: colorFor(g.name) }}>
                    {(g.name || '?').trim().charAt(0).toUpperCase()}
                  </span>
                  <span className="g-text">
                    <span className="g-name">{g.name}</span>
                    <span className="g-email">{g.email}</span>
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}
