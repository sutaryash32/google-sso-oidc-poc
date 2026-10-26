package com.secufusion.oidcpoc.tenant;

import java.util.Collection;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

/** A validated JWT authentication that also carries the tenant resolved from its claims. */
public class TenantAuthentication extends JwtAuthenticationToken {

    private final TenantContext tenantContext;

    public TenantAuthentication(Jwt jwt, Collection<? extends GrantedAuthority> authorities, TenantContext tenantContext) {
        super(jwt, authorities, jwt.getSubject());
        this.tenantContext = tenantContext;
    }

    public TenantContext tenantContext() {
        return tenantContext;
    }
}
