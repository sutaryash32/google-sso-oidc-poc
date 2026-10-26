package com.secufusion.oidcpoc.tenant;

import com.secufusion.oidcpoc.config.RepoPaths;
import java.nio.file.Path;
import java.util.List;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;

/**
 * Multi-tenant security. Validation layers, in order:
 *   1. signature + issuer + expiry (default validators),
 *   2. audience must include this API,
 *   3. tenant_id / tenant_domain / sub must be present,
 *   4. (per request, in TenantContextFilter) the tenant must exist, own that domain, be active and SSO-enabled.
 */
@Configuration
@EnableWebSecurity
@EnableConfigurationProperties(TenantProperties.class)
public class TenantSecurityConfig {

    @Bean
    public JwtDecoder jwtDecoder(TenantProperties props) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(props.jwkSetUri()).build();
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer(props.issuer()),
                new AudienceValidator(props.audience()),
                new TenantClaimsValidator()));
        return decoder;
    }

    @Bean
    public TenantDirectory tenantDirectory(TenantProperties props) {
        // Fail fast: without the registry nobody could sign in, and a silent "deny everyone" is hard to diagnose.
        Path file = RepoPaths.find(props.registryFile()).orElseThrow(() -> new IllegalStateException(
                "Tenant registry not found: '" + props.registryFile() + "' (looked in the working directory "
                        + Path.of("").toAbsolutePath() + " and its parents). Set TENANT_REGISTRY_FILE to its absolute path."));
        return new FileTenantDirectory(file);
    }

    @Bean
    public SecurityFilterChain tenantSecurityFilterChain(HttpSecurity http, TenantDirectory directory,
                                                         TenantProperties props) throws Exception {
        return http
                .cors(cors -> cors.configurationSource(request -> {
                    CorsConfiguration config = new CorsConfiguration();
                    config.setAllowedOrigins(props.corsAllowedOrigins() == null ? List.of() : props.corsAllowedOrigins());
                    config.setAllowedMethods(List.of("GET", "POST", "OPTIONS"));
                    config.setAllowedHeaders(List.of("Authorization", "Content-Type"));
                    return config;
                }))
                .csrf(csrf -> csrf.disable())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(a -> a
                        .requestMatchers("/api/public").permitAll()
                        .anyRequest().authenticated())
                .oauth2ResourceServer(o -> o.jwt(j -> j.jwtAuthenticationConverter(new TenantJwtConverter())))
                // Not a @Component on purpose: a Filter bean would also be auto-registered outside the security chain.
                .addFilterAfter(new TenantContextFilter(directory), BearerTokenAuthenticationFilter.class)
                .build();
    }
}
