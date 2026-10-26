package com.secufusion.oidcpoc.tenant;

import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

/** Multi-tenant settings (see the app.tenant block in application.yml). */
@ConfigurationProperties(prefix = "app.tenant")
public record TenantProperties(
        String issuer,
        String jwkSetUri,
        String audience,
        String registryFile,
        List<String> corsAllowedOrigins,
        Datasource datasource) {

    public record Datasource(String url, String username, String password) {
    }
}
