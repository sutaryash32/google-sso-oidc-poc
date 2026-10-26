package com.secufusion.spike.tenant;

/**
 * Pure decision logic: given the facts from a verified Google ID token and the login context, decide whether the
 * login may proceed and for which tenant. No Keycloak types here so it is unit-testable and reusable by backends.
 *
 * The authoritative input is the {@code hd} claim. Email domain and the discovery hint are only cross-checks; they
 * can deny but never grant.
 */
public final class TenantResolver {

    public enum Reason {
        OK,
        MISSING_HD,
        EMAIL_MISSING,
        EMAIL_NOT_VERIFIED,
        UNKNOWN_DOMAIN,
        AMBIGUOUS_DOMAIN,
        TENANT_SUSPENDED,
        SSO_DISABLED,
        EMAIL_DOMAIN_MISMATCH,
        HINT_MISMATCH,
        USER_TENANT_CONFLICT,
        USER_IDENTITY_CONFLICT
    }

    /**
     * @param hd                    hosted-domain claim from the verified ID token (nullable)
     * @param email                 email claim
     * @param emailVerified         email_verified claim
     * @param loginHint             the discovery hint sent by the app (nullable; only an email-shaped hint is used)
     * @param existingUserTenantId  tenant already bound to the Keycloak user for this identity (nullable)
     * @param idpSubject            the provider's subject for this login (Google "sub"; nullable only in legacy callers)
     * @param existingUserIdpSubject provider subject already recorded on the Keycloak user (nullable)
     */
    public record Input(String hd, String email, boolean emailVerified, String loginHint, String existingUserTenantId,
                        String idpSubject, String existingUserIdpSubject) {

        public Input(String hd, String email, boolean emailVerified, String loginHint, String existingUserTenantId) {
            this(hd, email, emailVerified, loginHint, existingUserTenantId, null, null);
        }
    }

    public record Decision(boolean allowed, Reason reason, Tenant tenant, String detail) {
        static Decision deny(Reason reason, String detail) {
            return new Decision(false, reason, null, detail);
        }

        static Decision allow(Tenant tenant) {
            return new Decision(true, Reason.OK, tenant, "tenant=" + tenant.tenantId());
        }
    }

    private final TenantRegistry registry;

    public TenantResolver(TenantRegistry registry) {
        this.registry = registry;
    }

    public Decision decide(Input in) {
        String hd = Domains.normalize(in.hd());
        if (hd == null) {
            return Decision.deny(Reason.MISSING_HD, "ID token has no hd claim (not a managed Google organization account)");
        }
        if (in.email() == null || in.email().isBlank()) {
            return Decision.deny(Reason.EMAIL_MISSING, "ID token has no email");
        }
        if (!in.emailVerified()) {
            return Decision.deny(Reason.EMAIL_NOT_VERIFIED, "email_verified is not true");
        }

        TenantRegistry.Lookup byHd = registry.lookupDomain(hd);
        if (byHd.kind() == TenantRegistry.Kind.AMBIGUOUS) {
            return Decision.deny(Reason.AMBIGUOUS_DOMAIN, "domain claimed by more than one tenant: " + hd);
        }
        if (byHd.kind() == TenantRegistry.Kind.NOT_FOUND) {
            return Decision.deny(Reason.UNKNOWN_DOMAIN, "hd not registered: " + hd);
        }
        Tenant tenant = byHd.tenant();
        if (!tenant.active()) {
            return Decision.deny(Reason.TENANT_SUSPENDED, "tenant not active: " + tenant.tenantId());
        }
        if (!tenant.ssoEnabled()) {
            return Decision.deny(Reason.SSO_DISABLED, "SSO disabled for tenant: " + tenant.tenantId());
        }

        // Cross-check 1: the email's domain must belong to the same tenant as hd.
        String emailDomain = Domains.domainOfEmail(in.email());
        if (!sameTenant(emailDomain, tenant)) {
            return Decision.deny(Reason.EMAIL_DOMAIN_MISMATCH,
                    "email domain " + emailDomain + " does not belong to tenant " + tenant.tenantId() + " (hd=" + hd + ")");
        }

        // Cross-check 2: the tenant discovered before login must equal the authenticated tenant.
        String hintDomain = Domains.domainOfEmail(in.loginHint());
        if (hintDomain != null && !sameTenant(hintDomain, tenant)) {
            return Decision.deny(Reason.HINT_MISMATCH,
                    "discovered domain " + hintDomain + " is not tenant " + tenant.tenantId() + " (hd=" + hd + ")");
        }

        // Cross-check 3: an already-provisioned user must not move between tenants.
        String existing = in.existingUserTenantId();
        if (existing != null && !existing.isBlank() && !existing.equals(tenant.tenantId())) {
            return Decision.deny(Reason.USER_TENANT_CONFLICT,
                    "user bound to tenant " + existing + " but hd resolves to " + tenant.tenantId());
        }

        // Cross-check 4: the Keycloak user must still be the same provider identity it was created for.
        String recorded = in.existingUserIdpSubject();
        if (recorded != null && !recorded.isBlank() && in.idpSubject() != null && !recorded.equals(in.idpSubject())) {
            return Decision.deny(Reason.USER_IDENTITY_CONFLICT,
                    "user was provisioned for provider subject " + recorded + " but this login is " + in.idpSubject());
        }

        return Decision.allow(tenant);
    }

    private boolean sameTenant(String domain, Tenant tenant) {
        if (domain == null) {
            return false;
        }
        TenantRegistry.Lookup l = registry.lookupDomain(domain);
        return l.kind() == TenantRegistry.Kind.FOUND && l.tenant().tenantId().equals(tenant.tenantId());
    }
}
