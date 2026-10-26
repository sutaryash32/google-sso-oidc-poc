package com.secufusion.spike.tenant;

import com.secufusion.spike.tenant.TenantResolver.Decision;
import com.secufusion.spike.tenant.TenantResolver.Input;
import com.secufusion.spike.tenant.TenantResolver.Reason;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TenantResolverTest {

    private static final Tenant ACME = new Tenant("t-acme", "Acme", true, true, Set.of("acme.com", "acme.co.uk"));
    private static final Tenant GLOBEX = new Tenant("t-globex", "Globex", true, true, Set.of("globex.com"));
    private static final Tenant INITECH = new Tenant("t-initech", "Initech", false, true, Set.of("initech.com"));
    private static final Tenant HOOLI = new Tenant("t-hooli", "Hooli", true, false, Set.of("hooli.com"));
    private static final Tenant DUP_A = new Tenant("t-dup-a", "DupA", true, true, Set.of("dup.com"));
    private static final Tenant DUP_B = new Tenant("t-dup-b", "DupB", true, true, Set.of("dup.com"));

    private final TenantResolver resolver = new TenantResolver(registryOf(ACME, GLOBEX, INITECH, HOOLI, DUP_A, DUP_B));

    private static TenantRegistry registryOf(Tenant... tenants) {
        Map<String, List<Tenant>> index = new HashMap<>();
        for (Tenant t : tenants) {
            for (String d : t.domains()) {
                index.computeIfAbsent(d, k -> new java.util.ArrayList<>()).add(t);
            }
        }
        return domain -> {
            List<Tenant> owners = index.get(domain);
            if (owners == null) return TenantRegistry.Lookup.NOT_FOUND;
            return owners.size() > 1 ? TenantRegistry.Lookup.AMBIGUOUS : TenantRegistry.Lookup.found(owners.get(0));
        };
    }

    private static Input in(String hd, String email) {
        return new Input(hd, email, true, null, null);
    }

    @Test
    void knownActiveTenantIsAllowed() {
        Decision d = resolver.decide(in("acme.com", "alice@acme.com"));
        assertTrue(d.allowed());
        assertEquals("t-acme", d.tenant().tenantId());
    }

    @Test
    void hdAndEmailAreCaseInsensitive() {
        Decision d = resolver.decide(in("ACME.COM", "Alice@Acme.Com"));
        assertTrue(d.allowed());
        assertEquals("t-acme", d.tenant().tenantId());
    }

    @Test
    void secondaryDomainOfSameTenantIsAllowedForEmail() {
        Decision d = resolver.decide(in("acme.com", "alice@acme.co.uk"));
        assertTrue(d.allowed());
        assertEquals("t-acme", d.tenant().tenantId());
    }

    @Test
    void missingHdIsDenied() {
        assertEquals(Reason.MISSING_HD, resolver.decide(in(null, "eve@gmail.com")).reason());
        assertEquals(Reason.MISSING_HD, resolver.decide(in("  ", "eve@gmail.com")).reason());
    }

    @Test
    void unverifiedEmailIsDenied() {
        Decision d = resolver.decide(new Input("acme.com", "alice@acme.com", false, null, null));
        assertEquals(Reason.EMAIL_NOT_VERIFIED, d.reason());
    }

    @Test
    void unknownDomainIsDenied() {
        assertEquals(Reason.UNKNOWN_DOMAIN, resolver.decide(in("unknown.com", "x@unknown.com")).reason());
    }

    @Test
    void lookalikeDomainsNeverMatchBySuffixOrPrefix() {
        assertEquals(Reason.UNKNOWN_DOMAIN, resolver.decide(in("acme.com.evil.com", "x@acme.com.evil.com")).reason());
        assertEquals(Reason.UNKNOWN_DOMAIN, resolver.decide(in("mail.acme.com", "x@mail.acme.com")).reason());
        assertEquals(Reason.UNKNOWN_DOMAIN, resolver.decide(in("evil-acme.com", "x@evil-acme.com")).reason());
    }

    @Test
    void suspendedAndSsoDisabledTenantsAreDenied() {
        assertEquals(Reason.TENANT_SUSPENDED, resolver.decide(in("initech.com", "d@initech.com")).reason());
        assertEquals(Reason.SSO_DISABLED, resolver.decide(in("hooli.com", "h@hooli.com")).reason());
    }

    @Test
    void domainClaimedByTwoTenantsIsDenied() {
        assertEquals(Reason.AMBIGUOUS_DOMAIN, resolver.decide(in("dup.com", "x@dup.com")).reason());
    }

    @Test
    void emailInAnotherTenantsDomainIsDenied() {
        Decision d = resolver.decide(in("acme.com", "mallory@globex.com"));
        assertEquals(Reason.EMAIL_DOMAIN_MISMATCH, d.reason());
    }

    @Test
    void emailInUnregisteredDomainIsDenied() {
        assertEquals(Reason.EMAIL_DOMAIN_MISMATCH, resolver.decide(in("acme.com", "x@other.org")).reason());
    }

    @Test
    void discoveryHintForAnotherTenantIsDenied() {
        Decision d = resolver.decide(new Input("globex.com", "zed@globex.com", true, "zed@acme.com", null));
        assertEquals(Reason.HINT_MISMATCH, d.reason());
    }

    @Test
    void discoveryHintForUnregisteredDomainIsDenied() {
        Decision d = resolver.decide(new Input("acme.com", "a@acme.com", true, "a@nowhere.io", null));
        assertEquals(Reason.HINT_MISMATCH, d.reason());
    }

    @Test
    void matchingOrAbsentOrNonEmailHintIsAllowed() {
        assertTrue(resolver.decide(new Input("acme.com", "a@acme.com", true, "a@acme.co.uk", null)).allowed());
        assertTrue(resolver.decide(new Input("acme.com", "a@acme.com", true, null, null)).allowed());
        assertTrue(resolver.decide(new Input("acme.com", "a@acme.com", true, "not-an-email", null)).allowed());
    }

    @Test
    void userBoundToAnotherTenantIsDenied() {
        Decision d = resolver.decide(new Input("acme.com", "a@acme.com", true, null, "t-globex"));
        assertEquals(Reason.USER_TENANT_CONFLICT, d.reason());
    }

    @Test
    void userBoundToSameTenantIsAllowed() {
        assertTrue(resolver.decide(new Input("acme.com", "a@acme.com", true, null, "t-acme")).allowed());
    }

    @Test
    void emailWithoutDomainIsDenied() {
        assertFalse(resolver.decide(in("acme.com", "no-at-sign")).allowed());
        assertFalse(resolver.decide(in("acme.com", "trailing@")).allowed());
    }

    @Test
    void denialNeverCarriesATenant() {
        assertEquals(null, resolver.decide(in("unknown.com", "x@unknown.com")).tenant());
    }
}
