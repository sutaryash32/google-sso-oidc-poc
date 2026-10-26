package com.secufusion.oidcpoc.tenant;

import java.util.Optional;

/** Read side of the tenant control plane. The spike reads a JSON file; production calls the registry API. */
public interface TenantDirectory {

    Optional<TenantInfo> findByTenantId(String tenantId);
}
