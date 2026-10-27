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

    /**
     * The tenant that owns this domain, for choosing the realm to sign in to. Empty if no tenant owns it, or if more than one
     * does (ambiguous). Callers decide whether an inactive tenant may be revealed.
     */
    default Optional<TenantInfo> findByDomain(String domain) {
        return Optional.empty();
    }
}
