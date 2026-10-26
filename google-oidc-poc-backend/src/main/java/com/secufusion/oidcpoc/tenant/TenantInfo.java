package com.secufusion.oidcpoc.tenant;

import java.util.Set;

/**
 * What the API needs to know about a tenant to decide whether to serve it.
 *
 * @param groupsDelegatedAdmin the Workspace admin the service account impersonates to read this tenant's
 *                             groups; null means group sync is not configured for the tenant
 */
public record TenantInfo(String tenantId, String name, boolean active, boolean ssoEnabled,
                         Set<String> domains, String groupsDelegatedAdmin) {

    public TenantInfo(String tenantId, String name, boolean active, boolean ssoEnabled, Set<String> domains) {
        this(tenantId, name, active, ssoEnabled, domains, null);
    }
}
