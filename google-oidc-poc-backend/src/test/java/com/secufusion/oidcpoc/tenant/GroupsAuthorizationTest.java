package com.secufusion.oidcpoc.tenant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.secufusion.oidcpoc.controller.UserGroupsController;
import com.secufusion.oidcpoc.dto.UserGroupsResponse;
import com.secufusion.oidcpoc.service.GoogleGroupsService;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.Jwt;

/** The rules that stop the service account from being used across tenants. */
class GroupsAuthorizationTest {

    private final GoogleGroupsService service = mock(GoogleGroupsService.class);

    private static final TenantInfo YSERIOUS = new TenantInfo("t-yserious", "Yserious", true, true,
            Set.of("yserious.com"), "yash@yserious.com");
    private static final TenantInfo NO_GROUPS = new TenantInfo("t-globex", "Globex", true, true,
            Set.of("globex.com"), null);
    private static final TenantInfo EVIL_ADMIN = new TenantInfo("t-acme", "Acme", true, true,
            Set.of("acme.com"), "admin@yserious.com"); // delegated admin belongs to ANOTHER organization

    private final TenantDirectory directory = id -> Optional.ofNullable(switch (id) {
        case "t-yserious" -> YSERIOUS;
        case "t-globex" -> NO_GROUPS;
        case "t-acme" -> EVIL_ADMIN;
        default -> null;
    });

    private final UserGroupsController controller = new UserGroupsController(service, directory);

    @AfterEach
    void clear() {
        TenantContextHolder.clear();
    }

    private static Jwt tokenWithEmail(String email) {
        return Jwt.withTokenValue("t").header("alg", "RS256").subject("sub-1").claim("email", email)
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60)).build();
    }

    private static void actAs(String tenantId, String domain, String email) {
        TenantContextHolder.set(new TenantContext(tenantId, domain, "kc-sub-1", "google", "g-1", email));
    }

    @Test
    void ownGroupsAreFetchedThroughTheTenantsDelegatedAdmin() {
        actAs("t-yserious", "yserious.com", "yash@yserious.com");
        UserGroupsResponse body = new UserGroupsResponse("yash@yserious.com", List.of());
        when(service.fetchGroupsForUser("yash@yserious.com", "yash@yserious.com")).thenReturn(body);

        ResponseEntity<?> r = controller.getGroupsForUser("yash@yserious.com", tokenWithEmail("yash@yserious.com"));

        assertEquals(HttpStatus.OK, r.getStatusCode());
        assertEquals(body, r.getBody());
    }

    @Test
    void emailComparisonIgnoresCase() {
        actAs("t-yserious", "yserious.com", "yash@yserious.com");
        when(service.fetchGroupsForUser(anyString(), anyString())).thenReturn(new UserGroupsResponse("x", List.of()));
        ResponseEntity<?> r = controller.getGroupsForUser("Yash@Yserious.com", tokenWithEmail("yash@yserious.com"));
        assertEquals(HttpStatus.OK, r.getStatusCode());
    }

    @Test
    void anotherUsersEmailIsForbiddenAndNeverReachesGoogle() {
        actAs("t-yserious", "yserious.com", "yash@yserious.com");
        ResponseEntity<?> r = controller.getGroupsForUser("boss@yserious.com", tokenWithEmail("yash@yserious.com"));
        assertEquals(HttpStatus.FORBIDDEN, r.getStatusCode());
        verify(service, never()).fetchGroupsForUser(any(), any());
    }

    @Test
    void anEmailOutsideTheTokensTenantIsForbidden() {
        // Token says yash@yserious.com but the caller is (somehow) acting for another tenant's domain set.
        actAs("t-globex", "globex.com", "yash@yserious.com");
        ResponseEntity<?> r = controller.getGroupsForUser("yash@yserious.com", tokenWithEmail("yash@yserious.com"));
        assertEquals(HttpStatus.FORBIDDEN, r.getStatusCode());
        verify(service, never()).fetchGroupsForUser(any(), any());
    }

    @Test
    void aTenantWithoutGroupSyncGets501AndNoGoogleCall() {
        actAs("t-globex", "globex.com", "bob@globex.com");
        ResponseEntity<?> r = controller.getGroupsForUser("bob@globex.com", tokenWithEmail("bob@globex.com"));
        assertEquals(HttpStatus.NOT_IMPLEMENTED, r.getStatusCode());
        assertTrue(r.getBody().toString().contains("groups_not_configured_for_tenant"));
        verify(service, never()).fetchGroupsForUser(any(), any());
    }

    @Test
    void aDelegatedAdminFromAnotherOrganizationIsNeverImpersonated() {
        actAs("t-acme", "acme.com", "alice@acme.com");
        ResponseEntity<?> r = controller.getGroupsForUser("alice@acme.com", tokenWithEmail("alice@acme.com"));
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, r.getStatusCode());
        assertTrue(r.getBody().toString().contains("groups_misconfigured_for_tenant"));
        verify(service, never()).fetchGroupsForUser(any(), any());
    }

    @Test
    void aTokenWithoutAnEmailIsForbidden() {
        actAs("t-yserious", "yserious.com", "yash@yserious.com");
        Jwt noEmail = Jwt.withTokenValue("t").header("alg", "RS256").subject("s").claim("k", "v")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60)).build();
        assertEquals(HttpStatus.FORBIDDEN, controller.getGroupsForUser("yash@yserious.com", noEmail).getStatusCode());
    }
}
