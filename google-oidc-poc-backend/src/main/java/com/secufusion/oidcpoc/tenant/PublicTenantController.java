package com.secufusion.oidcpoc.tenant;

import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Unauthenticated: the sign-in page asks which realm to log in to for an organization's domain. It answers with the realm name
 * only, and answers the same 404 for a domain that is not a tenant, a tenant that is suspended or has SSO off, and one that has no
 * realm of its own, so it does not reveal tenant state. It reveals only whether a domain is a serviceable tenant.
 */
@RestController
@RequestMapping("/api/public")
public class PublicTenantController {

    /** Keycloak's issuer URL ends with /realms/<name>. */
    private static final Pattern REALM = Pattern.compile("/realms/([A-Za-z0-9][A-Za-z0-9_-]*)/?$");

    private final TenantDirectory directory;

    public PublicTenantController(TenantDirectory directory) {
        this.directory = directory;
    }

    @GetMapping("/tenant")
    public ResponseEntity<Map<String, String>> realmFor(@RequestParam("domain") String domain) {
        Optional<TenantInfo> tenant = domain == null || domain.length() > 253 ? Optional.empty()
                : directory.findByDomain(domain.trim().toLowerCase(Locale.ROOT));
        Optional<String> realm = tenant.filter(t -> t.active() && t.ssoEnabled()).map(TenantInfo::issuer).map(PublicTenantController::realmOf);
        return realm.map(r -> ResponseEntity.ok(Map.of("realm", r)))
                .orElseGet(() -> ResponseEntity.status(404).body(Map.of("error", "unknown_tenant")));
    }

    static String realmOf(String issuer) {
        if (issuer == null) {
            return null;
        }
        Matcher m = REALM.matcher(issuer.trim());
        return m.find() ? m.group(1) : null;
    }
}
