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
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.ErrorPageException;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Enforces the tenant at the identity-broker boundary.
 *
 * Why a mapper and not a post-login authenticator: {@link #preprocessFederatedIdentity} runs on every brokered login
 * BEFORE any Keycloak user is created or linked, and it sees the already-validated ID token. A denied login therefore
 * leaves nothing behind.
 *
 * Responsibilities:
 *   1. preprocess: resolve hd -> tenant via the registry and deny on any failed check;
 *   2. import/update: write the admin-only attributes on the user, which protocol mappers then copy into tokens:
 *        tenant_id, tenant_domain   which tenant the user belongs to;
 *        idp_alias, idp_subject     the provider identity (for Google: the "sub" claim), the stable person key. The
 *                                   Keycloak user id is NOT stable (it changes if the user is deleted and re-linked).
 *
 * It is independent of the Google provider's own hd check on purpose (see CVE-2026-18214 discussion): tenancy must
 * not rest on a single validation layer.
 */
public class TenantResolverMapper extends AbstractIdentityProviderMapper {

    public static final String PROVIDER_ID = "tenant-resolver-mapper";
    public static final String CONFIG_REGISTRY_FILE = "registry.file";
    /** Spike aid: log the (non-secret) ID token claims of every login. Contains personal data; keep off in production. */
    public static final String CONFIG_LOG_CLAIMS = "log.claims";

    public static final String ATTR_TENANT_ID = "tenant_id";
    public static final String ATTR_TENANT_DOMAIN = "tenant_domain";
    public static final String ATTR_IDP_ALIAS = "idp_alias";
    public static final String ATTR_IDP_SUBJECT = "idp_subject";

    static final String DENY_MESSAGE_KEY = "access-denied";

    private static final String CTX_TENANT_ID = "spike.tenant_id";
    private static final String CTX_TENANT_DOMAIN = "spike.tenant_domain";
    private static final String CTX_IDP_ALIAS = "spike.idp_alias";
    private static final String CTX_IDP_SUBJECT = "spike.idp_subject";

    private static final Logger LOG = Logger.getLogger(TenantResolverMapper.class);

    private static final List<ProviderConfigProperty> CONFIG = List.of(
            new ProviderConfigProperty(CONFIG_REGISTRY_FILE, "Registry file",
                    "Path to the tenant registry JSON (falls back to env TENANT_REGISTRY_FILE, then " + Registries.DEFAULT_REGISTRY_FILE + ").",
                    ProviderConfigProperty.STRING_TYPE, null),
            new ProviderConfigProperty(CONFIG_LOG_CLAIMS, "Log ID token claims",
                    "Log the ID token's claims for every login (contains personal data; spike use only).",
                    ProviderConfigProperty.BOOLEAN_TYPE, "false"));

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
        return "Tenant Resolver (hd -> registry)";
    }

    @Override
    public String getHelpText() {
        return "Resolves the tenant from the verified hd claim, denies unknown/suspended/mismatched logins "
                + "before user creation, and stamps tenant and provider-identity attributes on the user.";
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
        String idpSubject = context.getId();

        if (isTrue(model, CONFIG_LOG_CLAIMS)) {
            logClaims(idpAlias, idToken);
        }

        String email = Registries.firstNonBlank(asString(claims.get("email")), context.getEmail());
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String hint = authSession == null ? null : authSession.getClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM);

        UserModel existing = session.users().getUserByFederatedIdentity(realm,
                new FederatedIdentityModel(idpAlias, idpSubject, context.getUsername()));
        String existingTenant = existing == null ? null : existing.getFirstAttribute(ATTR_TENANT_ID);
        String existingIdpSubject = existing == null ? null : existing.getFirstAttribute(ATTR_IDP_SUBJECT);

        TenantResolver.Decision decision = new TenantResolver(Registries.forConfiguredPath(configured(model))).decide(
                new TenantResolver.Input(asString(claims.get("hd")), email, asBoolean(claims.get("email_verified")),
                        hint, existingTenant, idpSubject, existingIdpSubject));

        if (!decision.allowed()) {
            LOG.warnf("TENANT_DENIED reason=%s idp=%s sub=%s detail=%s",
                    decision.reason(), idpAlias, idpSubject, decision.detail());
            throw new ErrorPageException(session, authSession, Response.Status.FORBIDDEN, DENY_MESSAGE_KEY);
        }

        Tenant tenant = decision.tenant();
        context.getContextData().put(CTX_TENANT_ID, tenant.tenantId());
        context.getContextData().put(CTX_TENANT_DOMAIN, Domains.normalize(asString(claims.get("hd"))));
        context.getContextData().put(CTX_IDP_ALIAS, idpAlias);
        context.getContextData().put(CTX_IDP_SUBJECT, idpSubject);
        LOG.infof("TENANT_RESOLVED tenant=%s hd=%s idp=%s sub=%s", tenant.tenantId(),
                asString(claims.get("hd")), idpAlias, idpSubject);
    }

    @Override
    public void importNewUser(KeycloakSession session, RealmModel realm, UserModel user,
                              IdentityProviderMapperModel model, BrokeredIdentityContext context) {
        stamp(session, user, context);
    }

    @Override
    public void updateBrokeredUser(KeycloakSession session, RealmModel realm, UserModel user,
                                   IdentityProviderMapperModel model, BrokeredIdentityContext context) {
        stamp(session, user, context);
    }

    @Override
    public void updateBrokeredUserLegacy(KeycloakSession session, RealmModel realm, UserModel user,
                                         IdentityProviderMapperModel model, BrokeredIdentityContext context) {
        stamp(session, user, context);
    }

    /** Writes the tenant and provider identity onto the user; fails closed if the preprocess result is missing or conflicts. */
    private void stamp(KeycloakSession session, UserModel user, BrokeredIdentityContext context) {
        String tenantId = asString(context.getContextData().get(CTX_TENANT_ID));
        String tenantDomain = asString(context.getContextData().get(CTX_TENANT_DOMAIN));
        String idpAlias = asString(context.getContextData().get(CTX_IDP_ALIAS));
        String idpSubject = asString(context.getContextData().get(CTX_IDP_SUBJECT));
        if (tenantId == null || tenantDomain == null || idpAlias == null || idpSubject == null) {
            deny(session, context, "NO_RESOLUTION", user, "preprocess result missing");
        }
        String currentTenant = user.getFirstAttribute(ATTR_TENANT_ID);
        if (currentTenant != null && !currentTenant.equals(tenantId)) {
            deny(session, context, "USER_TENANT_CONFLICT", user, "bound=" + currentTenant + " resolved=" + tenantId);
        }
        String currentSubject = user.getFirstAttribute(ATTR_IDP_SUBJECT);
        if (currentSubject != null && !currentSubject.equals(idpSubject)) {
            deny(session, context, "USER_IDENTITY_CONFLICT", user, "recorded=" + currentSubject + " presented=" + idpSubject);
        }
        user.setSingleAttribute(ATTR_TENANT_ID, tenantId);
        user.setSingleAttribute(ATTR_TENANT_DOMAIN, tenantDomain);
        user.setSingleAttribute(ATTR_IDP_ALIAS, idpAlias);
        user.setSingleAttribute(ATTR_IDP_SUBJECT, idpSubject);
    }

    private static void deny(KeycloakSession session, BrokeredIdentityContext context, String reason, UserModel user, String detail) {
        LOG.errorf("TENANT_DENIED reason=%s user=%s %s", reason, user.getId(), detail);
        throw new ErrorPageException(session, context.getAuthenticationSession(), Response.Status.FORBIDDEN, DENY_MESSAGE_KEY);
    }

    private static void logClaims(String idpAlias, JsonWebToken idToken) {
        if (idToken == null) {
            LOG.infof("GOOGLE_CLAIMS idp=%s (no validated ID token in context)", idpAlias);
            return;
        }
        Map<String, Object> all = new LinkedHashMap<>();
        all.put("iss", idToken.getIssuer());
        all.put("aud", idToken.getAudience());
        all.put("azp", idToken.getIssuedFor());
        all.put("sub", idToken.getSubject());
        all.putAll(idToken.getOtherClaims());
        try {
            LOG.infof("GOOGLE_CLAIMS idp=%s claims=%s", idpAlias, JsonSerialization.writeValueAsString(all));
        } catch (Exception e) {
            LOG.warnf("GOOGLE_CLAIMS idp=%s (could not serialise claims: %s)", idpAlias, e.getMessage());
        }
    }

    private static String configured(IdentityProviderMapperModel model) {
        return model.getConfig() == null ? null : model.getConfig().get(CONFIG_REGISTRY_FILE);
    }

    private static boolean isTrue(IdentityProviderMapperModel model, String key) {
        return model.getConfig() != null && Boolean.parseBoolean(model.getConfig().get(key));
    }

    private static String asString(Object o) {
        return o == null ? null : o.toString();
    }

    private static boolean asBoolean(Object o) {
        return o instanceof Boolean b ? b : o != null && Boolean.parseBoolean(o.toString());
    }
}
