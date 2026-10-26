package com.secufusion.spike.tenant;

import com.secufusion.spike.tenant.TenantResolver.Decision;
import com.secufusion.spike.tenant.TenantResolver.Input;
import com.secufusion.spike.tenant.TenantResolver.Reason;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The provider-subject consistency rule: a Keycloak user must stay bound to the identity it was created for. */
class TenantResolverIdentityTest {

    private static final Tenant ACME = new Tenant("t-acme", "Acme", true, true, Set.of("acme.com"));

    private final TenantResolver resolver = new TenantResolver(domain ->
            domain.equals("acme.com") ? TenantRegistry.Lookup.found(ACME) : TenantRegistry.Lookup.NOT_FOUND);

    private Decision decide(String idpSubject, String recordedSubject) {
        return resolver.decide(new Input("acme.com", "a@acme.com", true, null, "t-acme", idpSubject, recordedSubject));
    }

    @Test
    void sameProviderSubjectIsAllowed() {
        assertTrue(decide("g-1", "g-1").allowed());
    }

    @Test
    void aDifferentProviderSubjectOnAnExistingUserIsDenied() {
        Decision d = decide("g-2", "g-1");
        assertEquals(Reason.USER_IDENTITY_CONFLICT, d.reason());
    }

    @Test
    void aUserWithNoRecordedSubjectYetIsAllowedSoLegacyUsersCanBeStamped() {
        assertTrue(decide("g-1", null).allowed());
        assertTrue(decide("g-1", "").allowed());
    }

    @Test
    void callersThatDoNotKnowTheSubjectAreNotBlocked() {
        assertTrue(resolver.decide(new Input("acme.com", "a@acme.com", true, null, null)).allowed());
    }

    @Test
    void tenantConflictIsReportedBeforeIdentityConflict() {
        Decision d = resolver.decide(new Input("acme.com", "a@acme.com", true, null, "t-other", "g-2", "g-1"));
        assertEquals(Reason.USER_TENANT_CONFLICT, d.reason());
    }
}
