package com.secufusion.oidcpoc.controller;

import com.secufusion.oidcpoc.service.GoogleGroupsService;
import com.secufusion.oidcpoc.tenant.TenantContext;
import com.secufusion.oidcpoc.tenant.TenantContextHolder;
import com.secufusion.oidcpoc.tenant.TenantDirectory;
import com.secufusion.oidcpoc.tenant.TenantInfo;
import java.util.Locale;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/**
 * Google groups for the caller. Keycloak gives us authentication; Google never puts group membership
 * in the ID token, so this endpoint fetches it from the Directory API.
 *
 * Tenant rules (all enforced here, none taken from the request):
 *   - the path email must equal the token's email: callers can only read their own groups;
 *   - the email's domain must belong to the token's tenant;
 *   - group lookup only works for tenants that have a delegated admin in the registry, and that
 *     admin's domain must itself belong to the tenant, so one tenant can never cause the service
 *     account to impersonate inside another organization.
 */
@RestController
public class UserGroupsController {

    private static final Logger log = LoggerFactory.getLogger(UserGroupsController.class);

    private final GoogleGroupsService googleGroupsService;
    private final TenantDirectory tenantDirectory;

    public UserGroupsController(GoogleGroupsService googleGroupsService, TenantDirectory tenantDirectory) {
        this.googleGroupsService = googleGroupsService;
        this.tenantDirectory = tenantDirectory;
    }

    @GetMapping("/api/users/{email}/groups")
    public ResponseEntity<?> getGroupsForUser(@PathVariable String email, @AuthenticationPrincipal Jwt jwt) {
        String tokenEmail = jwt.getClaimAsString("email");
        if (tokenEmail == null || !tokenEmail.equalsIgnoreCase(email)) {
            log.warn("Rejected groups request: path email does not match the token's email");
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }

        TenantContext ctx = TenantContextHolder.require();
        TenantInfo tenant = tenantDirectory.findByTenantId(ctx.tenantId()).orElse(null);
        if (tenant == null || !tenant.domains().contains(domainOf(email))) {
            log.warn("Rejected groups request: email domain does not belong to tenant {}", ctx.tenantId());
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }

        String admin = tenant.groupsDelegatedAdmin();
        if (admin == null) {
            return ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED)
                    .body(Map.of("error", "groups_not_configured_for_tenant"));
        }
        if (!tenant.domains().contains(domainOf(admin))) {
            log.error("Tenant {} has a delegated admin outside its own domains; refusing to impersonate", tenant.tenantId());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "groups_misconfigured_for_tenant"));
        }

        try {
            return ResponseEntity.ok(googleGroupsService.fetchGroupsForUser(admin, email));
        } catch (GoogleGroupsService.GoogleGroupsFetchException e) {
            log.error("Failed to fetch groups for user {}: {}", email, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    private static String domainOf(String email) {
        int at = email.lastIndexOf('@');
        return at < 0 ? "" : email.substring(at + 1).trim().toLowerCase(Locale.ROOT);
    }
}
