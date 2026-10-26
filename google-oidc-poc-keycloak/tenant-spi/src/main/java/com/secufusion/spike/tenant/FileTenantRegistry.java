package com.secufusion.spike.tenant;

import com.fasterxml.jackson.databind.JsonNode;
import org.jboss.logging.Logger;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.LongSupplier;

/**
 * JSON-file registry that reloads when the file's mtime changes.
 *
 * Failure policy (fail closed): until the file has loaded, every lookup is NOT_FOUND. After that, a snapshot is only
 * trusted while it is KNOWN to be current: the file was readable and unchanged, or was reloaded successfully, within
 * {@code maxStaleness}. If the file becomes unreadable or corrupt, the last good snapshot is served for at most that
 * long and then everything is denied. Without this bound a suspension made while the registry is unreachable would
 * never be noticed.
 *
 * A domain claimed by more than one tenant is AMBIGUOUS and denied, because an inconsistent registry must never
 * decide which tenant a login belongs to.
 */
public class FileTenantRegistry implements TenantRegistry {

    private static final Logger LOG = Logger.getLogger(FileTenantRegistry.class);

    /** Default bound on snapshot age; override with TENANT_REGISTRY_MAX_STALENESS_SECONDS. */
    public static final Duration DEFAULT_MAX_STALENESS = Duration.ofMinutes(15);

    private final Path file;
    private final Duration maxStaleness;
    private final LongSupplier clockMillis;

    private volatile Map<String, List<Tenant>> byDomain = Map.of();
    private volatile Map<String, Tenant> byId = Map.of();
    private volatile long loadedMtime = Long.MIN_VALUE;
    /** Last moment the snapshot was known to match the file. Long.MIN_VALUE until the first successful load. */
    private volatile long lastKnownCurrentMillis = Long.MIN_VALUE;

    public FileTenantRegistry(Path file) {
        this(file, defaultMaxStaleness(), System::currentTimeMillis);
    }

    public FileTenantRegistry(Path file, Duration maxStaleness, LongSupplier clockMillis) {
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
                LOG.warnf("Ignoring invalid TENANT_REGISTRY_MAX_STALENESS_SECONDS=%s", configured);
            }
        }
        return DEFAULT_MAX_STALENESS;
    }

    @Override
    public Lookup lookupDomain(String normalizedDomain) {
        if (!trusted()) {
            return Lookup.NOT_FOUND;
        }
        List<Tenant> owners = byDomain.get(normalizedDomain);
        if (owners == null || owners.isEmpty()) {
            return Lookup.NOT_FOUND;
        }
        return owners.size() > 1 ? Lookup.AMBIGUOUS : Lookup.found(owners.get(0));
    }

    @Override
    public Optional<Tenant> lookupTenant(String tenantId) {
        if (!trusted() || tenantId == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(byId.get(tenantId));
    }

    /** Re-checks the file, then reports whether the snapshot is known to be current within the staleness bound. */
    private boolean trusted() {
        reloadIfChanged();
        long last = lastKnownCurrentMillis;
        if (last == Long.MIN_VALUE) {
            return false;
        }
        boolean fresh = clockMillis.getAsLong() - last <= maxStaleness.toMillis();
        if (!fresh) {
            LOG.errorf("Tenant registry snapshot is older than %s and the file cannot be re-read: denying everything (%s)",
                    maxStaleness, file);
        }
        return fresh;
    }

    private synchronized void reloadIfChanged() {
        long mtime;
        try {
            mtime = Files.getLastModifiedTime(file).toMillis();
        } catch (IOException e) {
            LOG.warnf("Tenant registry file not readable: %s", file);
            return; // snapshot age keeps growing
        }
        if (mtime == loadedMtime) {
            lastKnownCurrentMillis = clockMillis.getAsLong(); // unchanged and readable: still current
            return;
        }
        try {
            List<Tenant> tenants = parse(JsonSerialization.mapper.readTree(Files.readAllBytes(file)));
            Map<String, List<Tenant>> domainIndex = new HashMap<>();
            Map<String, Tenant> idIndex = new HashMap<>();
            for (Tenant tenant : tenants) {
                idIndex.put(tenant.tenantId(), tenant);
                for (String domain : tenant.domains()) {
                    List<Tenant> owners = domainIndex.computeIfAbsent(domain, k -> new ArrayList<>());
                    if (owners.stream().noneMatch(o -> o.tenantId().equals(tenant.tenantId()))) {
                        owners.add(tenant);
                    }
                }
            }
            byDomain = domainIndex;
            byId = idIndex;
            loadedMtime = mtime;
            lastKnownCurrentMillis = clockMillis.getAsLong();
            LOG.infof("Tenant registry loaded: %d domains, %d tenants from %s", domainIndex.size(), idIndex.size(), file);
        } catch (Exception e) {
            LOG.warnf(e, "Tenant registry reload failed, keeping the previous snapshot until it goes stale: %s", file);
        }
    }

    static List<Tenant> parse(JsonNode root) {
        List<Tenant> tenants = new ArrayList<>();
        for (JsonNode t : root.path("tenants")) {
            Set<String> domains = new LinkedHashSet<>();
            for (JsonNode d : t.path("domains")) {
                String n = Domains.normalize(d.asText());
                if (n != null) {
                    domains.add(n);
                }
            }
            tenants.add(new Tenant(
                    t.path("tenantId").asText(),
                    t.path("name").asText(),
                    "active".equalsIgnoreCase(t.path("status").asText()),
                    t.path("ssoEnabled").asBoolean(false),
                    domains));
        }
        return tenants;
    }
}
