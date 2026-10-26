package com.secufusion.oidcpoc.tenant;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;

/**
 * Chooses how to validate a token from its (unverified) issuer, for a realm-per-tenant deployment: each tenant has its own
 * Keycloak realm and therefore its own issuer and signing keys.
 *
 * Only issuers the registry binds to an existing tenant are trusted, plus, optionally, one configured legacy issuer. An
 * unknown issuer resolves to nothing, so it is never contacted (no key fetch for an attacker-chosen URL) and its tokens are
 * rejected. The directory is consulted on EVERY request before a cached validator is handed out, so a tenant removed from
 * the registry stops being accepted at once. Per issuer the usual layers apply: signature against that realm's keys, the
 * issuer itself, expiry, audience, and the tenant claims. Which TENANT the token may speak for is checked afterwards in
 * {@link TenantContextFilter}.
 */
public class TenantIssuerResolver implements AuthenticationManagerResolver<String> {

    /** Keycloak's key endpoint, relative to a realm's issuer URL. */
    static final String CERTS_PATH = "/protocol/openid-connect/certs";

    private final TenantDirectory directory;
    private final String legacyIssuer;
    private final String legacyJwkSetUri;
    private final String audience;
    private final Map<String, AuthenticationManager> managers = new ConcurrentHashMap<>();

    /** @param legacyIssuer / legacyJwkSetUri the single pre-hub issuer, or blank for none */
    public TenantIssuerResolver(TenantDirectory directory, String legacyIssuer, String legacyJwkSetUri, String audience) {
        this.directory = directory;
        this.legacyIssuer = FileTenantDirectory.normalizeIssuer(legacyIssuer);
        this.legacyJwkSetUri = legacyJwkSetUri == null || legacyJwkSetUri.isBlank() ? null : legacyJwkSetUri.trim();
        this.audience = audience;
    }

    @Override
    public AuthenticationManager resolve(String issuer) {
        String key = FileTenantDirectory.normalizeIssuer(issuer);
        if (key == null) {
            return null;
        }
        if (legacyIssuer != null && legacyJwkSetUri != null && legacyIssuer.equals(key)) {
            return managers.computeIfAbsent(key, k -> manager(k, legacyJwkSetUri));
        }
        if (directory.findByIssuer(key).isEmpty()) {
            return null; // not bound to any (usable) tenant: not trusted
        }
        return managers.computeIfAbsent(key, k -> manager(k, k + CERTS_PATH));
    }

    private AuthenticationManager manager(String issuer, String jwkSetUri) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer(issuer),
                new AudienceValidator(audience),
                new TenantClaimsValidator()));
        JwtAuthenticationProvider provider = new JwtAuthenticationProvider(decoder);
        provider.setJwtAuthenticationConverter(new TenantJwtConverter());
        return new ProviderManager(provider);
    }
}
