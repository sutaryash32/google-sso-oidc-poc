package com.secufusion.spike.tenant;

import java.util.Optional;

/**
 * Domain registry abstraction. The prototype implementation reads a JSON file; production would call the
 * control-plane API with a short-TTL cache. Either way the resolver depends only on this interface.
 */
public interface TenantRegistry {

    enum Kind { FOUND, NOT_FOUND, AMBIGUOUS }

    record Lookup(Kind kind, Tenant tenant) {
        public static final Lookup NOT_FOUND = new Lookup(Kind.NOT_FOUND, null);
        public static final Lookup AMBIGUOUS = new Lookup(Kind.AMBIGUOUS, null);

        public static Lookup found(Tenant tenant) {
            return new Lookup(Kind.FOUND, tenant);
        }
    }

    /** @param normalizedDomain already passed through {@link Domains#normalize}. */
    Lookup lookupDomain(String normalizedDomain);

    /**
     * The tenant with this id, used for token-time checks (a tenant is identified by id once a user exists, not by
     * domain). Empty when unknown, or when the registry is too stale to be trusted.
     */
    default Optional<Tenant> lookupTenant(String tenantId) {
        return Optional.empty();
    }
}
