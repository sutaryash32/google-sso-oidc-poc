package com.secufusion.oidcpoc.tenant;

import java.util.Optional;

/** Read side of the tenant control plane. The spike reads a JSON file; production calls the registry API. */
public interface TenantDirectory {

    Optional<TenantInfo> findByTenantId(String tenantId);

    /**
     * The tenant whose own Keycloak realm issues tokens with this issuer URL. Empty if no tenant is bound to it, or if the
     * registry binds it to more than one tenant (ambiguous, so unusable). Used to decide which issuers are trusted at all.
     */
    default Optional<TenantInfo> findByIssuer(String issuer) {
        return Optional.empty();
    }
}
