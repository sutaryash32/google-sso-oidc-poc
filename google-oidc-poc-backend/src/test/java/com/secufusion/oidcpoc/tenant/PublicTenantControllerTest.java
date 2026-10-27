package com.secufusion.oidcpoc.tenant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PublicTenantControllerTest {

    @TempDir
    Path dir;

    private PublicTenantController controllerFor(String json) throws Exception {
        Path f = dir.resolve("registry.json");
        Files.writeString(f, json);
        return new PublicTenantController(new FileTenantDirectory(f));
    }

    private static final String REGISTRY = """
            {"tenants":[
              {"tenantId":"t-a","status":"active","ssoEnabled":true,"domains":["A.com","a.co.uk"],"issuer":"http://kc/realms/a"},
              {"tenantId":"t-b","status":"suspended","ssoEnabled":true,"domains":["b.com"],"issuer":"http://kc/realms/b"},
              {"tenantId":"t-c","status":"active","ssoEnabled":false,"domains":["c.com"],"issuer":"http://kc/realms/c"},
              {"tenantId":"t-d","status":"active","ssoEnabled":true,"domains":["d.com"]},
              {"tenantId":"t-e","status":"active","ssoEnabled":true,"domains":["shared.com"],"issuer":"http://kc/realms/e"},
              {"tenantId":"t-f","status":"active","ssoEnabled":true,"domains":["shared.com"],"issuer":"http://kc/realms/f"}]}""";

    @Test
    void anActiveTenantResolvesToItsRealmForAnyOfItsDomains() throws Exception {
        PublicTenantController c = controllerFor(REGISTRY);
        assertEquals(Map.of("realm", "a"), c.realmFor("a.com").getBody());
        assertEquals(Map.of("realm", "a"), c.realmFor("  A.CO.UK ").getBody());
    }

    @Test
    void everythingElseIsTheSameUnknownTenantAnswer() throws Exception {
        PublicTenantController c = controllerFor(REGISTRY);
        for (String domain : new String[]{"b.com" /* suspended */, "c.com" /* sso off */, "d.com" /* no realm */,
                "shared.com" /* ambiguous */, "nobody.com", "", null}) {
            var response = c.realmFor(domain);
            assertEquals(404, response.getStatusCode().value(), String.valueOf(domain));
            assertEquals(Map.of("error", "unknown_tenant"), response.getBody(), String.valueOf(domain));
        }
    }

    @Test
    void anOversizedDomainIsRejectedWithoutALookup() throws Exception {
        assertEquals(404, controllerFor(REGISTRY).realmFor("x".repeat(300) + ".com").getStatusCode().value());
    }

    @Test
    void realmIsTheLastSegmentOfTheIssuer() {
        assertEquals("acme", PublicTenantController.realmOf("http://localhost:8280/realms/acme"));
        assertEquals("acme", PublicTenantController.realmOf("http://localhost:8280/realms/acme/"));
        assertEquals("8views", PublicTenantController.realmOf("https://kc.example.com/auth/realms/8views"));
        assertNull(PublicTenantController.realmOf("http://localhost:8280/other/acme"));
        assertNull(PublicTenantController.realmOf(null));
    }

    @Test
    void theDefaultDirectoryKnowsNoDomains() {
        TenantDirectory d = id -> Optional.of(new TenantInfo(id, "x", true, true, Set.of("x.com")));
        assertTrue(d.findByDomain("x.com").isEmpty());
    }
}
