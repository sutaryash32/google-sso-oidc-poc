package com.secufusion.oidcpoc.tenant;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Locale;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Runs after bearer-token authentication. Re-validates the token's tenant against the registry on
 * EVERY request (independent of Keycloak's own login-time check) and, only if it is serviceable,
 * publishes the {@link TenantContext} for the duration of the request.
 *
 * Denials use 403 with a short machine-readable error; the request never reaches a controller.
 */
public class TenantContextFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(TenantContextFilter.class);

    private final TenantDirectory directory;

    public TenantContextFilter(TenantDirectory directory) {
        this.directory = directory;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (!(auth instanceof TenantAuthentication tenantAuth)) {
            chain.doFilter(request, response); // public endpoint or not authenticated: nothing to scope
            return;
        }

        TenantContext ctx = tenantAuth.tenantContext();
        Optional<TenantInfo> tenant = directory.findByTenantId(ctx.tenantId());
        String denial = null;
        if (tenant.isEmpty()) {
            denial = "unknown_tenant";
        } else if (!tenant.get().domains().contains(ctx.tenantDomain().toLowerCase(Locale.ROOT))) {
            denial = "tenant_domain_mismatch";
        } else if (!tenant.get().active()) {
            denial = "tenant_suspended";
        } else if (!tenant.get().ssoEnabled()) {
            denial = "sso_disabled";
        } else {
            denial = issuerBinding(ctx, tenant.get());
        }

        if (denial != null) {
            log.warn("TENANT_REQUEST_DENIED reason={} tenant={} sub={}", denial, ctx.tenantId(), ctx.subject());
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write("{\"error\":\"" + denial + "\"}");
            return;
        }

        TenantContextHolder.set(ctx);
        try {
            chain.doFilter(request, response);
        } finally {
            TenantContextHolder.clear();
        }
    }

    /**
     * A realm can only speak for its own tenant. The tenant_id claim is written by whoever administers the issuing realm,
     * so it is not enough on its own: the issuer must be the one the registry binds to that tenant.
     *   - the issuer is bound to a tenant (hub-and-spoke): that must be the tenant the token claims;
     *   - the issuer is not bound to anyone (the single legacy issuer): the claimed tenant must not own a realm of its own.
     */
    private String issuerBinding(TenantContext ctx, TenantInfo claimed) {
        Optional<TenantInfo> owner = ctx.issuer() == null ? Optional.empty() : directory.findByIssuer(ctx.issuer());
        if (owner.isPresent()) {
            return owner.get().tenantId().equals(claimed.tenantId()) ? null : "issuer_mismatch";
        }
        return claimed.issuer() != null ? "issuer_mismatch" : null;
    }
}
