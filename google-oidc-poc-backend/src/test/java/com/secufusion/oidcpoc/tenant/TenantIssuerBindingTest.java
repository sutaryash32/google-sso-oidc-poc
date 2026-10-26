package com.secufusion.oidcpoc.tenant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import jakarta.servlet.FilterChain;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Realm-per-tenant: which issuers are trusted at all, and which tenant each issuer may speak for. The tenant_id claim is
 * written by whoever administers the issuing realm, so a realm that claims another tenant's id must be refused.
 */
class TenantIssuerBindingTest {

    private static final String YS_ISS = "http://kc/realms/yserious";
    private static final String ACME_ISS = "http://kc/realms/acme";
    private static final String LEGACY_ISS = "http://kc/realms/google-oidc-poc";

    private static final TenantInfo YSERIOUS = new TenantInfo("t-yserious", "Yserious", true, true, Set.of("yserious.com"), null, YS_ISS);
    private static final TenantInfo ACME = new TenantInfo("t-acme", "Acme", true, true, Set.of("acme.com"), null, ACME_ISS);
    private static final TenantInfo LEGACY_TENANT = new TenantInfo("t-old", "Old", true, true, Set.of("old.com"));

    /** In-memory directory that can change, to model a tenant being removed. */
    static class MapDirectory implements TenantDirectory {
        final Map<String, TenantInfo> byId = new HashMap<>();

        MapDirectory(TenantInfo... tenants) {
            for (TenantInfo t : tenants) byId.put(t.tenantId(), t);
        }

        @Override
        public Optional<TenantInfo> findByTenantId(String id) {
            return Optional.ofNullable(byId.get(id));
        }

        @Override
        public Optional<TenantInfo> findByIssuer(String issuer) {
            return byId.values().stream().filter(t -> issuer != null && issuer.equals(t.issuer())).findFirst();
        }
    }

    private final MapDirectory directory = new MapDirectory(YSERIOUS, ACME, LEGACY_TENANT);

    @AfterEach
    void cleanup() {
        SecurityContextHolder.clearContext();
    }

    private static void authenticate(String issuer, String tenantId, String domain) {
        Jwt.Builder b = Jwt.withTokenValue("t").header("alg", "RS256").subject("sub-1")
                .claim("tenant_id", tenantId).claim("tenant_domain", domain).claim("idp", "google").claim("idp_sub", "g-1")
                .claim("email", "a@" + domain).issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60));
        if (issuer != null) b.issuer(issuer);
        SecurityContextHolder.getContext().setAuthentication((TenantAuthentication) new TenantJwtConverter().convert(b.build()));
    }

    private MockHttpServletResponse run(AtomicReference<TenantContext> seen) throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = (req, res) -> seen.set(TenantContextHolder.require());
        new TenantContextFilter(directory).doFilter(new MockHttpServletRequest("GET", "/api/documents"), response, chain);
        return response;
    }

    // ---- the filter: an issuer may speak only for its own tenant ----------------------------------------------------

    @Test
    void aRealmMayActForItsOwnTenant() throws Exception {
        authenticate(ACME_ISS, "t-acme", "acme.com");
        AtomicReference<TenantContext> seen = new AtomicReference<>();
        assertEquals(200, run(seen).getStatus());
        assertEquals("t-acme", seen.get().tenantId());
        assertEquals(ACME_ISS, seen.get().issuer());
    }

    @Test
    void aRealmClaimingAnotherTenantsIdIsRefused() throws Exception {
        authenticate(ACME_ISS, "t-yserious", "yserious.com");     // acme's realm admin writes tenant_id=t-yserious
        AtomicReference<TenantContext> seen = new AtomicReference<>();
        MockHttpServletResponse response = run(seen);
        assertEquals(403, response.getStatus());
        assertTrue(response.getContentAsString().contains("issuer_mismatch"));
        assertNull(seen.get());
    }

    @Test
    void aTenantThatOwnsARealmCannotBeSpokenForByAnyOtherIssuer() throws Exception {
        authenticate(LEGACY_ISS, "t-yserious", "yserious.com");   // the legacy realm claims a tenant with its own realm
        MockHttpServletResponse response = run(new AtomicReference<>());
        assertEquals(403, response.getStatus());
        assertTrue(response.getContentAsString().contains("issuer_mismatch"));
    }

    @Test
    void aTokenWithoutAnIssuerCannotSpeakForARealmBoundTenant() throws Exception {
        authenticate(null, "t-acme", "acme.com");
        assertTrue(run(new AtomicReference<>()).getContentAsString().contains("issuer_mismatch"));
    }

    @Test
    void theLegacyIssuerStillServesTenantsWithoutTheirOwnRealm() throws Exception {
        authenticate(LEGACY_ISS, "t-old", "old.com");
        assertEquals(200, run(new AtomicReference<>()).getStatus());
    }

    @Test
    void aRealmBoundToATenantCannotActForALegacyTenant() throws Exception {
        authenticate(ACME_ISS, "t-old", "old.com");
        assertTrue(run(new AtomicReference<>()).getContentAsString().contains("issuer_mismatch"));
    }

    // ---- the resolver: which issuers are trusted at all ------------------------------------------------------------

    private static TenantIssuerResolver resolver(TenantDirectory d, String legacyIssuer) {
        return new TenantIssuerResolver(d, legacyIssuer, legacyIssuer == null ? null : legacyIssuer + "/protocol/openid-connect/certs", "api");
    }

    @Test
    void resolverTrustsRegistryIssuersOnly() {
        TenantIssuerResolver r = resolver(directory, null);
        assertNotNull(r.resolve(YS_ISS));
        assertNotNull(r.resolve(ACME_ISS));
        assertNull(r.resolve("http://evil.example/realms/yserious"));
        assertNull(r.resolve(LEGACY_ISS));        // not configured, not in the registry
        assertNull(r.resolve(null));
        assertNull(r.resolve("  "));
    }

    @Test
    void resolverIgnoresATrailingSlashAndReusesTheValidator() {
        TenantIssuerResolver r = resolver(directory, null);
        assertSame(r.resolve(YS_ISS), r.resolve(YS_ISS + "/"));
    }

    @Test
    void resolverTrustsTheLegacyIssuerOnlyWhenConfigured() {
        assertNotNull(resolver(directory, LEGACY_ISS).resolve(LEGACY_ISS));
        assertNull(resolver(directory, null).resolve(LEGACY_ISS));
        assertNull(resolver(directory, "").resolve(LEGACY_ISS));
    }

    @Test
    void aRemovedTenantsIssuerStopsBeingTrustedAtOnce() {
        TenantIssuerResolver r = resolver(directory, null);
        assertNotNull(r.resolve(ACME_ISS));       // a validator is now cached for acme
        directory.byId.remove("t-acme");
        assertNull(r.resolve(ACME_ISS));          // the cache does not keep it alive
    }

    // ---- the file directory: issuer parsing and ambiguity --------------------------------------------------------------

    @TempDir
    Path dir;

    private FileTenantDirectory fileDirectory(String json) throws Exception {
        Path f = dir.resolve("registry.json");
        Files.writeString(f, json);
        return new FileTenantDirectory(f);
    }

    @Test
    void fileDirectoryFindsATenantByItsIssuerIgnoringTrailingSlashes() throws Exception {
        FileTenantDirectory d = fileDirectory("""
                {"tenants":[
                  {"tenantId":"t-a","status":"active","ssoEnabled":true,"domains":["a.com"],"issuer":" http://kc/realms/a/ "},
                  {"tenantId":"t-b","status":"active","ssoEnabled":true,"domains":["b.com"]}]}""");
        assertEquals("t-a", d.findByIssuer("http://kc/realms/a").orElseThrow().tenantId());
        assertEquals("t-a", d.findByIssuer("http://kc/realms/a/").orElseThrow().tenantId());
        assertEquals("http://kc/realms/a", d.findByTenantId("t-a").orElseThrow().issuer());
        assertNull(d.findByTenantId("t-b").orElseThrow().issuer());
        assertTrue(d.findByIssuer("http://kc/realms/b").isEmpty());
        assertTrue(d.findByIssuer(null).isEmpty());
    }

    @Test
    void anIssuerClaimedByTwoTenantsIsTrustedForNeither() throws Exception {
        FileTenantDirectory d = fileDirectory("""
                {"tenants":[
                  {"tenantId":"t-a","status":"active","ssoEnabled":true,"domains":["a.com"],"issuer":"http://kc/realms/shared"},
                  {"tenantId":"t-b","status":"active","ssoEnabled":true,"domains":["b.com"],"issuer":"http://kc/realms/shared"},
                  {"tenantId":"t-c","status":"active","ssoEnabled":true,"domains":["c.com"],"issuer":"http://kc/realms/c"}]}""");
        assertTrue(d.findByIssuer("http://kc/realms/shared").isEmpty());
        assertEquals("t-c", d.findByIssuer("http://kc/realms/c").orElseThrow().tenantId());
    }

    @Test
    void anUnreadableRegistryTrustsNoIssuer() {
        FileTenantDirectory d = new FileTenantDirectory(dir.resolve("missing.json"));
        assertTrue(d.findByIssuer(YS_ISS).isEmpty());
    }
}
