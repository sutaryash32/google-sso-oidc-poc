package com.secufusion.spike.tenant;

import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.provider.AbstractIdentityProviderMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderSyncMode;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.ErrorPageException;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Tenant check for the hub-and-spoke model. It is used at two places, with the same logic:
 *
 *   - on a tenant realm's "google-hub" IdP: the domains are those of that one tenant, and the claims are the ones master
 *     passes on (google_hd, google_email_verified, google_sub);
 *   - on master's own Google IdP: the domains are those of ALL tenants, and the claims are Google's raw ones (hd,
 *     email_verified, sub), so a foreign organisation is refused at master and leaves no user there either.
 *
 * It runs in preprocessFederatedIdentity, i.e. BEFORE any user is created or linked in the realm, and it sees the
 * already-signature-validated ID token. It applies {@link HubTenantGate} against the "allowed.domains" of this mapper. A
 * denied login leaves nothing behind.
 *
 * It does not stamp attributes: the plain attribute importers on the same IdP copy the claims onto the user.
 * It does not depend on the Hosted Domain setting of master's Google IdP: that is a UI hint and a first line of defence,
 * not the tenant boundary.
 */
public class HubTenantGateMapper extends AbstractIdentityProviderMapper {

    public static final String PROVIDER_ID = "hub-tenant-gate-mapper";
    public static final String CONFIG_ALLOWED_DOMAINS = "allowed.domains";
    /**
     * Prefix of the claims to read. "google_" (default) on a tenant realm's google-hub IdP; empty on master's Google IdP,
     * which sees Google's raw claims hd / email_verified / sub.
     */
    public static final String CONFIG_CLAIM_PREFIX = "claim.prefix";
    /** Label in the log lines: "hub" on a tenant realm (default), "master" on master's Google IdP. */
    public static final String CONFIG_GATE_NAME = "gate.name";

    static final String DEFAULT_PREFIX = "google_";
    /** Setting value of {@link #CONFIG_CLAIM_PREFIX} meaning "read the raw claims hd / email_verified / sub". */
    static final String RAW_PREFIX = "raw";
    static final String DEFAULT_GATE_NAME = "hub";
    /** User attribute that records the Google subject, whatever the claim prefix. */
    static final String ATTR_SUBJECT = "google_sub";
    static final String DENY_MESSAGE_KEY = "access-denied";

    private static final Logger LOG = Logger.getLogger(HubTenantGateMapper.class);

    private static final List<ProviderConfigProperty> CONFIG = List.of(
            new ProviderConfigProperty(CONFIG_ALLOWED_DOMAINS, "Allowed domains",
                    "Comma-separated domains bound to this realm's tenant (primary and secondary); on master, all tenants' domains. "
                            + "Empty denies every login.",
                    ProviderConfigProperty.STRING_TYPE, null),
            new ProviderConfigProperty(CONFIG_CLAIM_PREFIX, "Claim prefix",
                    "\"google_\" on a tenant realm (claims passed on by master); \"raw\" on master's Google IdP (Google's own claims).",
                    ProviderConfigProperty.STRING_TYPE, DEFAULT_PREFIX),
            new ProviderConfigProperty(CONFIG_GATE_NAME, "Gate name",
                    "Label used in log lines: hub (tenant realm) or master.",
                    ProviderConfigProperty.STRING_TYPE, DEFAULT_GATE_NAME));

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String[] getCompatibleProviders() {
        return new String[]{ANY_PROVIDER};
    }

    @Override
    public String getDisplayCategory() {
        return "Tenant";
    }

    @Override
    public String getDisplayType() {
        return "Hub Tenant Gate (hd -> bound domains)";
    }

    @Override
    public String getHelpText() {
        return "Denies a brokered login, before user creation, unless the Google claims belong to a bound tenant domain.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG;
    }

    @Override
    public boolean supportsSyncMode(IdentityProviderSyncMode syncMode) {
        return true;
    }

    @Override
    public void preprocessFederatedIdentity(KeycloakSession session, RealmModel realm,
                                            IdentityProviderMapperModel model, BrokeredIdentityContext context) {
        JsonWebToken idToken = (JsonWebToken) context.getContextData().get(OIDCIdentityProvider.VALIDATED_ID_TOKEN);
        Map<String, Object> claims = idToken == null ? Map.of() : idToken.getOtherClaims();
        String idpAlias = context.getIdpConfig().getAlias();

        Map<String, String> config = model.getConfig() == null ? Map.of() : model.getConfig();
        Set<String> allowed = HubTenantGate.parseDomains(config.get(CONFIG_ALLOWED_DOMAINS));
        // "raw" means no prefix (master's Google IdP). A literal empty value is not used because Keycloak may drop empty
        // settings, and an absent one must not silently become "no prefix".
        String configuredPrefix = config.get(CONFIG_CLAIM_PREFIX);
        String prefix = configuredPrefix == null || configuredPrefix.isBlank() ? DEFAULT_PREFIX
                : RAW_PREFIX.equals(configuredPrefix.trim()) ? "" : configuredPrefix;
        String gateName = Registries.firstNonBlank(config.get(CONFIG_GATE_NAME), DEFAULT_GATE_NAME);

        String hd = claim(idToken, claims, prefix + "hd");
        String emailVerified = claim(idToken, claims, prefix + "email_verified");
        String subject = claim(idToken, claims, prefix + "sub");
        String email = Registries.firstNonBlank(asString(claims.get("email")), context.getEmail());

        // The Google subject already recorded for the realm user this login resolves to (federated link), if any.
        UserModel existing = session.users().getUserByFederatedIdentity(realm,
                new FederatedIdentityModel(idpAlias, context.getId(), context.getUsername()));
        String existingSubject = existing == null ? null : existing.getFirstAttribute(ATTR_SUBJECT);

        HubTenantGate.Decision decision = HubTenantGate.decide(
                new HubTenantGate.Input(allowed, hd, emailVerified, email, subject, existingSubject));

        if (!decision.allowed()) {
            LOG.warnf("TENANT_DENIED gate=%s realm=%s reason=%s idp=%s sub=%s detail=%s", gateName, realm.getName(),
                    decision.reason(), idpAlias, subject, decision.detail());
            throw new ErrorPageException(session, context.getAuthenticationSession(), Response.Status.FORBIDDEN, DENY_MESSAGE_KEY);
        }
        LOG.infof("TENANT_ALLOWED gate=%s realm=%s hd=%s idp=%s sub=%s", gateName, realm.getName(), hd, idpAlias, subject);
    }

    /** A claim of the validated ID token. "sub" is not among the "other" claims; it has its own accessor. */
    private static String claim(JsonWebToken idToken, Map<String, Object> other, String name) {
        if ("sub".equals(name)) {
            return idToken == null ? null : idToken.getSubject();
        }
        return asString(other.get(name));
    }

    private static String asString(Object o) {
        return o == null ? null : o.toString();
    }
}
