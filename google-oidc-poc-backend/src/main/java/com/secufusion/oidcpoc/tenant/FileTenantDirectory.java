package com.secufusion.oidcpoc.tenant;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.LongSupplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Reads the same registry file the Keycloak SPI uses and reloads when it changes, so suspending a
 * tenant takes effect on this API immediately (the access token stays valid until it expires, the
 * tenant status check does not).
 *
 * Failure policy (fail closed, same as the Keycloak side): until the file has loaded, every tenant is unknown. After
 * that, a snapshot is only trusted while it is KNOWN to be current: the file was readable and unchanged, or was reloaded
 * successfully, within the staleness bound (default 15 minutes; env TENANT_REGISTRY_MAX_STALENESS_SECONDS). If the file
 * becomes unreadable or corrupt, the last good snapshot is served for at most that long and then every tenant is
 * unknown (403). Without the bound, a suspension made while the registry is unreachable would never be noticed.
 */
public class FileTenantDirectory implements TenantDirectory {

    private static final Logger log = LoggerFactory.getLogger(FileTenantDirectory.class);

    public static final Duration DEFAULT_MAX_STALENESS = Duration.ofMinutes(15);

    private final Path file;
    private final Duration maxStaleness;
    private final LongSupplier clockMillis;
    private final ObjectMapper mapper = new ObjectMapper();
    private volatile Map<String, TenantInfo> byId = Map.of();
    private volatile Map<String, TenantInfo> byIssuer = Map.of();
    private volatile long loadedMtime = Long.MIN_VALUE;
    /** Last moment the snapshot was known to match the file; Long.MIN_VALUE until the first successful load. */
    private volatile long lastKnownCurrentMillis = Long.MIN_VALUE;

    public FileTenantDirectory(Path file) {
        this(file, defaultMaxStaleness(), System::currentTimeMillis);
    }

    public FileTenantDirectory(Path file, Duration maxStaleness, LongSupplier clockMillis) {
        this.file = file;
        this.maxStaleness = maxStaleness;
        this.clockMillis = clockMillis;
        reloadIfChanged();
    }

    private static Duration defaultMaxStaleness() {
        String configured = System.getenv("TENANT_REGISTRY_MAX_STALENESS_SECONDS");
        if (configured != null && !configured.isBlank()) {
            try {
                return Duration.ofSeconds(Long.parseLong(configured.trim()));
            } catch (NumberFormatException e) {
                log.warn("Ignoring invalid TENANT_REGISTRY_MAX_STALENESS_SECONDS={}", configured);
            }
        }
        return DEFAULT_MAX_STALENESS;
    }

    @Override
    public Optional<TenantInfo> findByTenantId(String tenantId) {
        reloadIfChanged();
        if (!snapshotIsCurrent()) {
            return Optional.empty();
        }
        return Optional.ofNullable(tenantId == null ? null : byId.get(tenantId));
    }

    @Override
    public Optional<TenantInfo> findByIssuer(String issuer) {
        reloadIfChanged();
        if (!snapshotIsCurrent()) {
            return Optional.empty();
        }
        String key = normalizeIssuer(issuer);
        return Optional.ofNullable(key == null ? null : byIssuer.get(key));
    }

    /** True while the snapshot is known to match the file (see the failure policy above). */
    private boolean snapshotIsCurrent() {
        long last = lastKnownCurrentMillis;
        if (last == Long.MIN_VALUE || clockMillis.getAsLong() - last > maxStaleness.toMillis()) {
            if (last != Long.MIN_VALUE) {
                log.error("Tenant registry snapshot is older than {} and the file cannot be re-read: treating every tenant as unknown ({})",
                        maxStaleness, file);
            }
            return false;
        }
        return true;
    }

    /** Trim and drop trailing slashes, so "http://kc/realms/a/" and "http://kc/realms/a" are one issuer. Null if blank. */
    static String normalizeIssuer(String issuer) {
        if (issuer == null) {
            return null;
        }
        String s = issuer.trim();
        while (s.endsWith("/")) {
            s = s.substring(0, s.length() - 1);
        }
        return s.isEmpty() ? null : s;
    }

    /**
     * issuer -> tenant. An issuer claimed by two tenants is left out entirely (fail closed): neither tenant can then be
     * reached through it, instead of one of them silently winning.
     */
    static Map<String, TenantInfo> indexByIssuer(Map<String, TenantInfo> tenants) {
        Map<String, TenantInfo> index = new HashMap<>();
        Set<String> ambiguous = new LinkedHashSet<>();
        for (TenantInfo t : tenants.values()) {
            String key = normalizeIssuer(t.issuer());
            if (key == null) {
                continue;
            }
            if (index.putIfAbsent(key, t) != null) {
                ambiguous.add(key);
            }
        }
        for (String key : ambiguous) {
            index.remove(key);
            log.error("Tenant registry binds issuer {} to more than one tenant: that issuer is not trusted", key);
        }
        return index;
    }

    private synchronized void reloadIfChanged() {
        long mtime;
        try {
            mtime = Files.getLastModifiedTime(file).toMillis();
        } catch (IOException e) {
            log.warn("Tenant registry file not readable: {}", file);
            return; // the snapshot keeps ageing
        }
        if (mtime == loadedMtime) {
            lastKnownCurrentMillis = clockMillis.getAsLong(); // unchanged and readable: still current
            return;
        }
        try {
            Map<String, TenantInfo> parsed = parse(mapper.readTree(Files.readAllBytes(file)));
            byIssuer = indexByIssuer(parsed);
            byId = parsed;
            loadedMtime = mtime;
            lastKnownCurrentMillis = clockMillis.getAsLong();
            log.info("Tenant registry loaded: {} tenants from {}", byId.size(), file);
        } catch (Exception e) {
            log.warn("Tenant registry reload failed, keeping the previous snapshot until it goes stale: {}", file, e);
        }
    }

    static Map<String, TenantInfo> parse(JsonNode root) {
        Map<String, TenantInfo> index = new HashMap<>();
        for (JsonNode t : root.path("tenants")) {
            Set<String> domains = new LinkedHashSet<>();
            for (JsonNode d : t.path("domains")) {
                domains.add(d.asText().trim().toLowerCase(Locale.ROOT));
            }
            TenantInfo info = new TenantInfo(
                    t.path("tenantId").asText(),
                    t.path("name").asText(),
                    "active".equalsIgnoreCase(t.path("status").asText()),
                    t.path("ssoEnabled").asBoolean(false),
                    domains,
                    t.path("groupsDelegatedAdmin").isTextual() && !t.path("groupsDelegatedAdmin").asText().isBlank()
                            ? t.path("groupsDelegatedAdmin").asText().trim().toLowerCase(Locale.ROOT) : null,
                    t.path("issuer").isTextual() ? normalizeIssuer(t.path("issuer").asText()) : null);
            index.put(info.tenantId(), info);
        }
        return index;
    }
}
