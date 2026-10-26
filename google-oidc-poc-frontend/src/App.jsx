import { useEffect, useState } from 'react';
import keycloak from './keycloak';
import './App.css';

const BACKEND_URL = 'http://localhost:8095';

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

  useEffect(() => {
    initKeycloak()
      .then((auth) => {
        setAuthenticated(auth);
        if (auth) {
          setUserEmail(keycloak.tokenParsed?.email);
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
    return (
      <div className="page">
        <div className="stack">
          <div className="card login">
            <h1>Google Workspace SSO</h1>
            <p>Sign in with your yserious.com account.</p>
            <button
              className="btn btn-primary"
              onClick={() => keycloak.login({ idpHint: 'google-oidc' })}
            >
              Sign in with Google Workspace
            </button>
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
          <div className="avatar" aria-hidden="true">{initial}</div>
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
                  <span className="g-name">{g.name}</span>
                  <span className="g-email">{g.email}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}
