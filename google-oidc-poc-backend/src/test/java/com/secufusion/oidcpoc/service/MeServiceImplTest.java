package com.secufusion.oidcpoc.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

class MeServiceImplTest {

    private final MeServiceImpl service = new MeServiceImpl();

    private static Jwt.Builder jwt() {
        return Jwt.withTokenValue("t").header("alg", "RS256").subject("kc-sub").claim("email", "a@acme.com")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60));
    }

    @Test
    void identityProviderComesFromTheIdpClaim() {
        assertEquals("google-oidc", service.buildUserInfo(jwt().claim("idp", "google-oidc").build()).identityProvider());
    }

    @Test
    void theOldClaimNameStillWorksAsAFallback() {
        assertEquals("google-oidc", service.buildUserInfo(jwt().claim("identity_provider", "google-oidc").build()).identityProvider());
    }

    @Test
    void idpWinsWhenBothArePresent() {
        assertEquals("new", service.buildUserInfo(jwt().claim("idp", "new").claim("identity_provider", "old").build()).identityProvider());
    }

    @Test
    void aBlankIdpFallsBackAndAbsenceGivesNull() {
        assertEquals("old", service.buildUserInfo(jwt().claim("idp", " ").claim("identity_provider", "old").build()).identityProvider());
        assertNull(service.buildUserInfo(jwt().build()).identityProvider());
    }
}
