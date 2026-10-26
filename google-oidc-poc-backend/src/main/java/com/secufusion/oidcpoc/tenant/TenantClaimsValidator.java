package com.secufusion.oidcpoc.tenant;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Fails closed when tenancy or identity claims are missing. Without enforcement upstream, Keycloak can issue a valid
 * token with no tenant at all (observed in the spike's negative control), so this API must never treat "no tenant" as
 * "any tenant". The provider identity claims (idp, idp_sub) are required too: they are the person key.
 */
public class TenantClaimsValidator implements OAuth2TokenValidator<Jwt> {

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        if (isBlank(jwt.getClaimAsString("tenant_id")) || isBlank(jwt.getClaimAsString("tenant_domain"))
                || isBlank(jwt.getClaimAsString("idp")) || isBlank(jwt.getClaimAsString("idp_sub"))
                || isBlank(jwt.getSubject())) {
            return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token",
                    "token is missing tenant_id / tenant_domain / idp / idp_sub / sub", null));
        }
        return OAuth2TokenValidatorResult.success();
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }
}
