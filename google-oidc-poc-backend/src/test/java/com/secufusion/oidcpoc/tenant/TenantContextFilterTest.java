package com.secufusion.oidcpoc.tenant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import jakarta.servlet.FilterChain;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

class TenantContextFilterTest {

    private static final TenantInfo ACME = new TenantInfo("t-acme", "Acme", true, true, Set.of("acme.com"));
    private static final TenantInfo SUSPENDED = new TenantInfo("t-initech", "Initech", false, true, Set.of("initech.com"));
    private static final TenantInfo NO_SSO = new TenantInfo("t-hooli", "Hooli", true, false, Set.of("hooli.com"));

    private final TenantDirectory directory = id -> Optional.ofNullable(
            switch (id) {
                case "t-acme" -> ACME;
                case "t-initech" -> SUSPENDED;
                case "t-hooli" -> NO_SSO;
                default -> null;
            });

    @AfterEach
    void cleanup() {
        SecurityContextHolder.clearContext();
    }

    private static TenantAuthentication authFor(String tenantId, String domain) {
        Jwt jwt = Jwt.withTokenValue("t").header("alg", "RS256").subject("sub-1")
                .claim("tenant_id", tenantId).claim("tenant_domain", domain).claim("idp", "google").claim("idp_sub", "g-1")
                .claim("email", "a@" + domain)
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60)).build();
        TenantAuthentication a = (TenantAuthentication) new TenantJwtConverter().convert(jwt);
        SecurityContextHolder.getContext().setAuthentication(a);
        return a;
    }

    private MockHttpServletResponse run(AtomicReference<TenantContext> seen) throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = (req, res) -> seen.set(TenantContextHolder.require());
        new TenantContextFilter(directory).doFilter(new MockHttpServletRequest("GET", "/api/documents"), response, chain);
        return response;
    }

    @Test
    void servesAnActiveTenantAndExposesItOnlyDuringTheRequest() throws Exception {
        authFor("t-acme", "acme.com");
        AtomicReference<TenantContext> seen = new AtomicReference<>();
        MockHttpServletResponse response = run(seen);

        assertEquals(200, response.getStatus());
        assertEquals("t-acme", seen.get().tenantId());
        assertThrows(TenantContextHolder.MissingTenantContextException.class, TenantContextHolder::require);
    }

    @Test
    void contextIsClearedEvenWhenTheChainThrows() {
        authFor("t-acme", "acme.com");
        FilterChain boom = (req, res) -> { throw new IllegalStateException("boom"); };
        assertThrows(IllegalStateException.class, () -> new TenantContextFilter(directory)
                .doFilter(new MockHttpServletRequest("GET", "/x"), new MockHttpServletResponse(), boom));
        assertThrows(TenantContextHolder.MissingTenantContextException.class, TenantContextHolder::require);
    }

    @Test
    void unknownTenantIsForbidden() throws Exception {
        authFor("t-nobody", "acme.com");
        AtomicReference<TenantContext> seen = new AtomicReference<>();
        MockHttpServletResponse response = run(seen);
        assertEquals(403, response.getStatus());
        assertTrue(response.getContentAsString().contains("unknown_tenant"));
        assertNull(seen.get());
    }

    @Test
    void domainNotOwnedByTheTokensTenantIsForbidden() throws Exception {
        authFor("t-acme", "globex.com");
        AtomicReference<TenantContext> seen = new AtomicReference<>();
        MockHttpServletResponse response = run(seen);
        assertEquals(403, response.getStatus());
        assertTrue(response.getContentAsString().contains("tenant_domain_mismatch"));
        assertNull(seen.get());
    }

    @Test
    void domainComparisonIsCaseInsensitive() throws Exception {
        authFor("t-acme", "ACME.com");
        AtomicReference<TenantContext> seen = new AtomicReference<>();
        assertEquals(200, run(seen).getStatus());
    }

    @Test
    void suspendedTenantIsForbiddenEvenWithAValidToken() throws Exception {
        authFor("t-initech", "initech.com");
        AtomicReference<TenantContext> seen = new AtomicReference<>();
        MockHttpServletResponse response = run(seen);
        assertEquals(403, response.getStatus());
        assertTrue(response.getContentAsString().contains("tenant_suspended"));
        assertNull(seen.get());
    }

    @Test
    void tenantWithSsoDisabledIsForbidden() throws Exception {
        authFor("t-hooli", "hooli.com");
        AtomicReference<TenantContext> seen = new AtomicReference<>();
        MockHttpServletResponse response = run(seen);
        assertEquals(403, response.getStatus());
        assertTrue(response.getContentAsString().contains("sso_disabled"));
    }

    @Test
    void requestsWithoutATenantAuthenticationPassThroughWithNoContext() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("someone", "x", List.of()));
        AtomicReference<Boolean> reached = new AtomicReference<>(false);
        FilterChain chain = (req, res) -> {
            reached.set(true);
            assertThrows(TenantContextHolder.MissingTenantContextException.class, TenantContextHolder::require);
        };
        new TenantContextFilter(directory).doFilter(new MockHttpServletRequest("GET", "/api/public"),
                new MockHttpServletResponse(), chain);
        assertTrue(reached.get());
    }
}
