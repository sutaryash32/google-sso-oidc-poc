package com.secufusion.oidcpoc.tenant;

import java.util.Set;

/**
 * What the API needs to know about a tenant to decide whether to serve it.
 *
 * @param groupsDelegatedAdmin the Workspace admin the service account impersonates to read this tenant's
 *                             groups; null means group sync is not configured for the tenant
 * @param issuer               the Keycloak realm that issues this tenant's tokens (hub-and-spoke: realm per tenant), as
 *                             its issuer URL; null for a tenant served by the single legacy issuer. When set, only tokens
 *                             from exactly this issuer can speak for the tenant, and this issuer can speak for no other
 */
public record TenantInfo(String tenantId, String name, boolean active, boolean ssoEnabled,
                         Set<String> domains, String groupsDelegatedAdmin, String issuer) {

    public TenantInfo(String tenantId, String name, boolean active, boolean ssoEnabled, Set<String> domains,
                      String groupsDelegatedAdmin) {
        this(tenantId, name, active, ssoEnabled, domains, groupsDelegatedAdmin, null);
    }

    public TenantInfo(String tenantId, String name, boolean active, boolean ssoEnabled, Set<String> domains) {
        this(tenantId, name, active, ssoEnabled, domains, null, null);
    }
}
