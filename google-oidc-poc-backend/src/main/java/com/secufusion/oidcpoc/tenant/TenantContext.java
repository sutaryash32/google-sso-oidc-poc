package com.secufusion.oidcpoc.tenant;

/**
 * The tenant and person a request acts for, derived ONLY from the validated JWT. Immutable; nothing in a request body,
 * path, query or header can change it.
 *
 * @param tenantId     the tenant: the only isolation key (tenantDomain is display-only and varies between users of a tenant)
 * @param idpAlias     the identity provider the user signed in through
 * @param idpSubject   that provider's own subject for the person (for Google, the "sub" claim). Together with the tenant
 *                     and alias this is the person key. The Keycloak user id ({@code subject}) is NOT stable: it changes
 *                     if the Keycloak user is deleted and re-linked.
 * @param subject      the Keycloak user id; informational only, never a key
 */
public record TenantContext(String tenantId, String tenantDomain, String subject, String idpAlias, String idpSubject,
                            String email) {
}
