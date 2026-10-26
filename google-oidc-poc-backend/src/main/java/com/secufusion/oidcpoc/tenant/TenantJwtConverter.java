package com.secufusion.oidcpoc.tenant;

import java.util.List;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;

/** Builds the tenant-aware authentication. Authorities are intentionally empty: roles are a later step. */
public class TenantJwtConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        TenantContext ctx = new TenantContext(
                jwt.getClaimAsString("tenant_id"),
                jwt.getClaimAsString("tenant_domain"),
                jwt.getSubject(),
                jwt.getClaimAsString("idp"),
                jwt.getClaimAsString("idp_sub"),
                jwt.getClaimAsString("email"));
        return new TenantAuthentication(jwt, List.of(), ctx);
    }
}
