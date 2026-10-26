package com.secufusion.oidcpoc.tenant;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

class TokenValidatorsTest {

    private static Jwt.Builder jwt() {
        return Jwt.withTokenValue("t").header("alg", "RS256").subject("sub-1")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60));
    }

    private static Jwt.Builder full() {
        return jwt().claim("tenant_id", "t-acme").claim("tenant_domain", "acme.com")
                .claim("idp", "google-oidc").claim("idp_sub", "1234567890");
    }

    // ---- audience ----

    @Test
    void tokenWithTheApiAudienceIsAccepted() {
        AudienceValidator v = new AudienceValidator("spike-api");
        assertFalse(v.validate(jwt().audience(List.of("spike-api")).claim("k", "v").build()).hasErrors());
        assertFalse(v.validate(jwt().audience(List.of("account", "spike-api")).build()).hasErrors());
    }

    @Test
    void tokenForAnotherAudienceIsRejected() {
        AudienceValidator v = new AudienceValidator("spike-api");
        assertTrue(v.validate(jwt().audience(List.of("account")).build()).hasErrors());
    }

    @Test
    void tokenWithNoAudienceIsRejected() {
        AudienceValidator v = new AudienceValidator("spike-api");
        assertTrue(v.validate(jwt().claim("k", "v").build()).hasErrors());
    }

    // ---- tenant and identity claims ----

    @Test
    void tokenWithAllTenantAndIdentityClaimsIsAccepted() {
        assertFalse(new TenantClaimsValidator().validate(full().build()).hasErrors());
    }

    @Test
    void tokenWithoutTenantIdIsRejected() {
        Jwt t = jwt().claim("tenant_domain", "acme.com").claim("idp", "google-oidc").claim("idp_sub", "1").build();
        assertTrue(new TenantClaimsValidator().validate(t).hasErrors());
    }

    @Test
    void tokenWithoutTenantDomainIsRejected() {
        Jwt t = jwt().claim("tenant_id", "t-acme").claim("idp", "google-oidc").claim("idp_sub", "1").build();
        assertTrue(new TenantClaimsValidator().validate(t).hasErrors());
    }

    @Test
    void tokenWithoutTheProviderIdentityIsRejected() {
        // The person key is (tenant, idp, idp_sub). A token that cannot supply it must not reach any data.
        Jwt noIdp = jwt().claim("tenant_id", "t-acme").claim("tenant_domain", "acme.com").claim("idp_sub", "1").build();
        Jwt noSub = jwt().claim("tenant_id", "t-acme").claim("tenant_domain", "acme.com").claim("idp", "google-oidc").build();
        assertTrue(new TenantClaimsValidator().validate(noIdp).hasErrors());
        assertTrue(new TenantClaimsValidator().validate(noSub).hasErrors());
    }

    @Test
    void blankClaimsAreRejected() {
        assertTrue(new TenantClaimsValidator().validate(full().claim("tenant_id", "  ").build()).hasErrors());
        assertTrue(new TenantClaimsValidator().validate(full().claim("tenant_domain", "").build()).hasErrors());
        assertTrue(new TenantClaimsValidator().validate(full().claim("idp", " ").build()).hasErrors());
        assertTrue(new TenantClaimsValidator().validate(full().claim("idp_sub", "").build()).hasErrors());
    }

    @Test
    void tokenWithoutSubjectIsRejected() {
        Jwt noSub = Jwt.withTokenValue("t").header("alg", "RS256")
                .claim("tenant_id", "t-acme").claim("tenant_domain", "acme.com").claim("idp", "google-oidc").claim("idp_sub", "1")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60)).build();
        assertTrue(new TenantClaimsValidator().validate(noSub).hasErrors());
    }
}
