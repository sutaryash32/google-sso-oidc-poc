// Realm configuration shared by every environment that runs the tenant plugin: the real realm, the mock-IdP test harness
// and the real-Google spike realm. Every function is idempotent and takes an `api(method, path, body)` bound to ONE realm
// (path is relative to /admin/realms/{realm}) that resolves to parsed JSON (null for an empty body).
//
// Nothing here knows secrets: it never reads or writes client secrets.

export const NO_EMAIL_LINK_FLOW = 'first broker login (no email linking)';
export const TENANT_ATTRIBUTES = ['tenant_id', 'tenant_domain', 'idp_alias', 'idp_subject'];

/** Admin-only user attributes: users can neither see nor change them (the account API rejects writes). */
export async function ensureUserProfileAttributes(api, log = console.log) {
  const profile = await api('GET', '/users/profile');
  let changed = false;
  for (const name of TENANT_ATTRIBUTES) {
    if (!profile.attributes.some((a) => a.name === name)) {
      profile.attributes.push({ name, displayName: name, permissions: { view: ['admin'], edit: ['admin'] }, validations: {} });
      changed = true;
    }
  }
  if (changed) await api('PUT', '/users/profile', profile);
  log(`  user profile: tenant/identity attributes ${changed ? 'added (admin-only)' : 'already present'}`);
}

const attributeMapper = (name, userAttribute = name, claim = name) => ({
  name,
  protocol: 'openid-connect',
  protocolMapper: 'oidc-usermodel-attribute-mapper',
  config: {
    'user.attribute': userAttribute, 'claim.name': claim, 'jsonType.label': 'String',
    'id.token.claim': 'true', 'access.token.claim': 'true', 'userinfo.token.claim': 'true',
  },
});

/**
 * Claims the backend relies on:
 *   tenant_id, tenant_domain   which tenant (tenant_domain is display only: it varies between users of one tenant)
 *   idp, idp_sub               provider alias and the provider's subject: the stable person key (Keycloak's own "sub"
 *                              changes if the Keycloak user is deleted and re-linked)
 */
export function tenantClaimMappers() {
  return [
    attributeMapper('tenant_id'),
    attributeMapper('tenant_domain'),
    attributeMapper('idp', 'idp_alias', 'idp'),
    attributeMapper('idp_sub', 'idp_subject', 'idp_sub'),
  ];
}

export const audienceMapper = (audience) => ({
  name: `${audience}-audience`,
  protocol: 'openid-connect',
  protocolMapper: 'oidc-audience-mapper',
  config: { 'included.custom.audience': audience, 'access.token.claim': 'true', 'id.token.claim': 'false' },
});

export const tenantGuardMapper = (registryFile) => ({
  name: 'tenant-guard',
  protocol: 'openid-connect',
  protocolMapper: 'tenant-guard-mapper',
  config: registryFile ? { 'registry.file': registryFile } : {},
});

/** Adds any of `mappers` the client does not have yet. Returns the names it created. */
export async function ensureClientMappers(api, clientId, mappers, log = console.log) {
  const client = (await api('GET', `/clients?clientId=${encodeURIComponent(clientId)}`))[0];
  if (!client) throw new Error(`client ${clientId} not found`);
  const existing = new Set((client.protocolMappers ?? []).map((m) => m.name));
  const created = [];
  for (const m of mappers) {
    if (existing.has(m.name)) continue;
    await api('POST', `/clients/${client.id}/protocol-mappers/models`, m);
    created.push(m.name);
  }
  log(`  client ${clientId}: mappers ${created.length ? `created (${created.join(', ')})` : 'already present'}`);
  return created;
}

/**
 * Copies Keycloak's "first broker login" flow and replaces its "Handle Existing Account" step (which can link a new
 * Google identity into an existing user that merely shares the email, after "Verify existing account by Email") with a
 * step that denies. The IdP is switched to the copy. Provider identity, not email, is the only link.
 */
export async function applyNoEmailLinking(api, idpAlias, log = console.log) {
  const enc = encodeURIComponent;
  const flows = await api('GET', '/authentication/flows');
  if (!flows.some((f) => f.alias === NO_EMAIL_LINK_FLOW)) {
    await api('POST', `/authentication/flows/${enc('first broker login')}/copy`, { newName: NO_EMAIL_LINK_FLOW });
    log(`  flow "${NO_EMAIL_LINK_FLOW}": created as a copy of "first broker login"`);
  }

  let execs = await api('GET', `/authentication/flows/${enc(NO_EMAIL_LINK_FLOW)}/executions`);
  const hasDeny = execs.some((e) => e.providerId === 'tenant-no-email-link');
  if (!hasDeny) {
    // The step must live in the subflow that holds "Create User If Unique": that is where an email match ends up.
    const createUnique = execs.find((e) => e.providerId === 'idp-create-user-if-unique');
    if (!createUnique) throw new Error('cannot find "Create User If Unique" in the copied flow');
    const allFlows = await api('GET', '/authentication/flows');
    const parent = allFlows.find((f) => f.id === createUnique.flowId) ?? null;
    const parentAlias = parent ? parent.alias : `${NO_EMAIL_LINK_FLOW} User creation or linking`;
    await api('POST', `/authentication/flows/${enc(parentAlias)}/executions/execution`, { provider: 'tenant-no-email-link' });
    log('  flow: added the "deny existing account" step');
    execs = await api('GET', `/authentication/flows/${enc(NO_EMAIL_LINK_FLOW)}/executions`);
  }

  const deny = execs.find((e) => e.providerId === 'tenant-no-email-link');
  if (deny.requirement !== 'ALTERNATIVE') {
    await api('PUT', `/authentication/flows/${enc(NO_EMAIL_LINK_FLOW)}/executions`, { ...deny, requirement: 'ALTERNATIVE' });
  }

  // A copied flow's subflows are renamed with the copy's name as a prefix, so match the end of the name.
  const handle = execs.find((e) => (e.displayName ?? '').endsWith('Handle Existing Account'));
  if (handle) {
    await api('DELETE', `/authentication/executions/${handle.id}`);
    log('  flow: removed "Handle Existing Account" (email-based linking)');
  }

  const idp = await api('GET', `/identity-provider/instances/${idpAlias}`);
  if (idp.firstBrokerLoginFlowAlias !== NO_EMAIL_LINK_FLOW) {
    idp.firstBrokerLoginFlowAlias = NO_EMAIL_LINK_FLOW;
    await api('PUT', `/identity-provider/instances/${idpAlias}`, idp);
    log(`  IdP ${idpAlias}: first broker login flow -> "${NO_EMAIL_LINK_FLOW}"`);
  } else {
    log(`  IdP ${idpAlias}: already uses "${NO_EMAIL_LINK_FLOW}"`);
  }
}

/** Reverts applyNoEmailLinking: points the IdP back at the built-in flow (the copy is left in place). */
export async function revertNoEmailLinking(api, idpAlias, log = console.log) {
  const idp = await api('GET', `/identity-provider/instances/${idpAlias}`);
  idp.firstBrokerLoginFlowAlias = 'first broker login';
  await api('PUT', `/identity-provider/instances/${idpAlias}`, idp);
  log(`  IdP ${idpAlias}: first broker login flow -> "first broker login" (built-in)`);
}

/**
 * Users created before the provider-identity attributes existed have none. Fill them from the user's federated identity
 * link (its userId IS the provider subject). Never overwrites a value that is already set.
 */
export async function backfillProviderIdentity(api, idpAlias, log = console.log) {
  const users = await api('GET', '/users?max=1000');
  let stamped = 0;
  for (const u of users) {
    if (u.attributes?.idp_subject?.[0]) continue;
    const links = await api('GET', `/users/${u.id}/federated-identity`);
    const link = links.find((l) => l.identityProvider === idpAlias);
    if (!link) continue;
    await api('PUT', `/users/${u.id}`, {
      ...u,
      attributes: { ...(u.attributes ?? {}), idp_alias: [idpAlias], idp_subject: [link.userId] },
    });
    stamped++;
    log(`  back-fill: ${u.email ?? u.username} -> ${idpAlias}/${link.userId}`);
  }
  log(`  back-fill (provider identity): ${stamped} user(s) stamped`);
}
