package com.secufusion.spike.tenant;

import java.util.Set;

/**
 * A customer organization as known to the platform. The tenantId is the only
 * identity; domains are attributes that currently map to it.
 */
public record Tenant(String tenantId, String name, boolean active, boolean ssoEnabled, Set<String> domains) {
}
