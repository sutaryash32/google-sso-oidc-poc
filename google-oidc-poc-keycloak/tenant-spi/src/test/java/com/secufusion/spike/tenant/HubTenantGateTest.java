package com.secufusion.spike.tenant;

import com.secufusion.spike.tenant.HubTenantGate.Decision;
import com.secufusion.spike.tenant.HubTenantGate.Input;
import com.secufusion.spike.tenant.HubTenantGate.Reason;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HubTenantGateTest {

    private static final Set<String> ACME = Set.of("acme.com", "acme.co.uk");
    private static final String SUB = "112233445566778899001";

    private static Decision decide(Set<String> allowed, String hd, String verified, String email, String sub, String existing) {
        return HubTenantGate.decide(new Input(allowed, hd, verified, email, sub, existing));
    }

    private static Decision good() {
        return decide(ACME, "acme.com", "true", "a@acme.com", SUB, null);
    }

    @Test
    void aMatchingVerifiedAccountIsAllowed() {
        assertTrue(good().allowed());
    }

    @Test
    void domainsAreComparedCaseInsensitivelyAndExactly() {
        assertTrue(decide(ACME, "ACME.com.", "TRUE", "A@Acme.COM", SUB, null).allowed());
        assertEquals(Reason.HD_NOT_ALLOWED, decide(ACME, "evilacme.com", "true", "a@evilacme.com", SUB, null).reason());
        assertEquals(Reason.HD_NOT_ALLOWED, decide(ACME, "sub.acme.com", "true", "a@sub.acme.com", SUB, null).reason());
    }

    @Test
    void anUnconfiguredRealmDeniesEverything() {
        assertEquals(Reason.NOT_CONFIGURED, decide(Set.of(), "acme.com", "true", "a@acme.com", SUB, null).reason());
        assertEquals(Reason.NOT_CONFIGURED, decide(null, "acme.com", "true", "a@acme.com", SUB, null).reason());
    }

    @Test
    void anotherOrganisationIsDenied() {
        Decision d = decide(ACME, "yserious.com", "true", "a@yserious.com", SUB, null);
        assertFalse(d.allowed());
        assertEquals(Reason.HD_NOT_ALLOWED, d.reason());
    }

    @Test
    void aMissingOrBlankHdIsDenied() {
        assertEquals(Reason.NO_HD, decide(ACME, null, "true", "a@acme.com", SUB, null).reason());
        assertEquals(Reason.NO_HD, decide(ACME, "  ", "true", "a@acme.com", SUB, null).reason());
    }

    @Test
    void emailMustBeVerified() {
        assertEquals(Reason.EMAIL_NOT_VERIFIED, decide(ACME, "acme.com", "false", "a@acme.com", SUB, null).reason());
        assertEquals(Reason.EMAIL_NOT_VERIFIED, decide(ACME, "acme.com", null, "a@acme.com", SUB, null).reason());
        assertEquals(Reason.EMAIL_NOT_VERIFIED, decide(ACME, "acme.com", "yes", "a@acme.com", SUB, null).reason());
    }

    @Test
    void theEmailDomainMustAlsoBelongToTheTenant() {
        assertEquals(Reason.EMAIL_DOMAIN_NOT_ALLOWED, decide(ACME, "acme.com", "true", "a@gmail.com", SUB, null).reason());
        assertEquals(Reason.NO_EMAIL, decide(ACME, "acme.com", "true", null, SUB, null).reason());
        assertEquals(Reason.NO_EMAIL, decide(ACME, "acme.com", "true", "not-an-email", SUB, null).reason());
    }

    @Test
    void aSecondaryDomainIsAllowedOnlyWhenBound() {
        assertTrue(decide(ACME, "acme.com", "true", "a@acme.co.uk", SUB, null).allowed());
        assertEquals(Reason.EMAIL_DOMAIN_NOT_ALLOWED,
                decide(Set.of("acme.com"), "acme.com", "true", "a@acme.co.uk", SUB, null).reason());
    }

    @Test
    void aStableSubjectIsRequired() {
        assertEquals(Reason.NO_SUBJECT, decide(ACME, "acme.com", "true", "a@acme.com", null, null).reason());
        assertEquals(Reason.NO_SUBJECT, decide(ACME, "acme.com", "true", "a@acme.com", " ", null).reason());
    }

    @Test
    void aDifferentSubjectForAnExistingUserIsAConflict() {
        assertTrue(decide(ACME, "acme.com", "true", "a@acme.com", SUB, SUB).allowed());
        assertEquals(Reason.SUBJECT_CONFLICT, decide(ACME, "acme.com", "true", "a@acme.com", SUB, "999").reason());
    }

    @Test
    void parseDomainsNormalisesAndDropsBlanks() {
        assertEquals(Set.of("a.com", "b.com"), HubTenantGate.parseDomains(" A.com , b.com.,, "));
        assertTrue(HubTenantGate.parseDomains(null).isEmpty());
        assertTrue(HubTenantGate.parseDomains("  ").isEmpty());
    }
}
