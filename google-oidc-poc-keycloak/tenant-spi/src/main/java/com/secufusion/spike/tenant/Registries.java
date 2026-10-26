package com.secufusion.spike.tenant;

import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** One shared registry instance per file, used by every Keycloak extension in this plugin. */
final class Registries {

    static final String DEFAULT_REGISTRY_FILE = "/opt/keycloak/tenant-registry.json";

    private static final Map<String, FileTenantRegistry> BY_PATH = new ConcurrentHashMap<>();

    private Registries() {
    }

    /** @param configured the per-extension setting (may be blank); falls back to env TENANT_REGISTRY_FILE, then the default. */
    static FileTenantRegistry forConfiguredPath(String configured) {
        String path = firstNonBlank(configured, System.getenv("TENANT_REGISTRY_FILE"), DEFAULT_REGISTRY_FILE);
        return BY_PATH.computeIfAbsent(path, p -> new FileTenantRegistry(Path.of(p)));
    }

    static String firstNonBlank(String... values) {
        for (String v : values) {
            if (v != null && !v.isBlank()) {
                return v;
            }
        }
        return null;
    }
}
