package com.secufusion.spike.tenant;

import java.util.LinkedHashSet;
import java.util.Set;

/**
 * The tenant check of the hub-and-spoke model, as pure logic (no Keycloak types), so it can be unit-tested.
 *
 * A tenant realm trusts the master realm for authentication, but master's Google IdP admits any account Google allows
 * through. Whether THIS realm's tenant owns the account is decided here, from the claims master passes on, against the
 * domains bound to the realm. Every check fails closed; a missing claim is a denial, never a pass.
 */
public final class HubTenantGate {

    public enum Reason {
        OK, NOT_CONFIGURED, NO_HD, HD_NOT_ALLOWED, EMAIL_NOT_VERIFIED, NO_EMAIL, EMAIL_DOMAIN_NOT_ALLOWED, NO_SUBJECT,
        SUBJECT_CONFLICT
    }

    public record Decision(boolean allowed, Reason reason, String detail) {
        static Decision ok() {
            return new Decision(true, Reason.OK, "");
        }

        static Decision deny(Reason reason, String detail) {
            return new Decision(false, reason, detail);
        }
    }

    /**
     * @param allowedDomains  the domains bound to this realm's tenant (its primary domain plus any secondary domains)
     * @param hd              Google's hosted-domain claim, as passed through master
     * @param emailVerified   Google's email_verified, as passed through master ("true" / "false" / null)
     * @param email           the account's email
     * @param subject         Google's stable subject for the person
     * @param existingSubject the Google subject already recorded on the realm user this login resolves to, or null
     */
    public record Input(Set<String> allowedDomains, String hd, String emailVerified, String email, String subject,
                        String existingSubject) {
    }

    private HubTenantGate() {
    }

    /** "a.com, B.com" -> {a.com, b.com}. Blank entries are dropped. */
    public static Set<String> parseDomains(String csv) {
        Set<String> out = new LinkedHashSet<>();
        if (csv != null) {
            for (String part : csv.split("[,\\s]+")) {
                String d = Domains.normalize(part);
                if (d != null) {
                    out.add(d);
                }
            }
        }
        return out;
    }

    public static Decision decide(Input in) {
        if (in.allowedDomains() == null || in.allowedDomains().isEmpty()) {
            return Decision.deny(Reason.NOT_CONFIGURED, "no domain is bound to this realm");
        }
        String hd = Domains.normalize(in.hd());
        if (hd == null) {
            return Decision.deny(Reason.NO_HD, "no hosted-domain claim (personal account, or the claim was not propagated)");
        }
        if (!in.allowedDomains().contains(hd)) {
            return Decision.deny(Reason.HD_NOT_ALLOWED, "hd=" + hd + " is not bound to this realm");
        }
        if (!"true".equalsIgnoreCase(in.emailVerified() == null ? "" : in.emailVerified().trim())) {
            return Decision.deny(Reason.EMAIL_NOT_VERIFIED, "email_verified=" + in.emailVerified());
        }
        String emailDomain = Domains.domainOfEmail(in.email());
        if (emailDomain == null) {
            return Decision.deny(Reason.NO_EMAIL, "no usable email address");
        }
        if (!in.allowedDomains().contains(emailDomain)) {
            return Decision.deny(Reason.EMAIL_DOMAIN_NOT_ALLOWED, "email domain " + emailDomain + " is not bound to this realm");
        }
        if (in.subject() == null || in.subject().isBlank()) {
            return Decision.deny(Reason.NO_SUBJECT, "no stable Google subject was propagated");
        }
        if (in.existingSubject() != null && !in.existingSubject().isBlank() && !in.existingSubject().equals(in.subject())) {
            return Decision.deny(Reason.SUBJECT_CONFLICT, "recorded=" + in.existingSubject() + " presented=" + in.subject());
        }
        return Decision.ok();
    }
}
