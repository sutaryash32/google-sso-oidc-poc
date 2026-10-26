package com.secufusion.spike.tenant;

import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;
import org.keycloak.services.ErrorResponseException;

import java.util.List;
import java.util.Optional;

/**
 * Token-time tenant check. The login-time check (TenantResolverMapper) only runs when a user signs in through the
 * identity provider; refresh tokens and SSO sessions then keep minting tokens for as long as they live, so suspending a
 * tenant in the registry would not stop users who are already signed in (demonstrated in test-harness/scripts/
 * e2e-attacks.mjs). This mapper runs on EVERY token issuance, including refresh and silent re-authentication, and
 * refuses to issue a token when the user's tenant is unknown, suspended or has SSO disabled.
 *
 * Fail closed: a user with no tenant_id attribute gets no token from a client that has this mapper, so attach it only
 * to clients meant for tenant users. It adds no claim; the tenant claims come from the attribute mappers.
 */
public class TenantGuardMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, OIDCIDTokenMapper {

    public static final String PROVIDER_ID = "tenant-guard-mapper";

    private static final Logger LOG = Logger.getLogger(TenantGuardMapper.class);

    private static final List<ProviderConfigProperty> CONFIG = List.of(
            new ProviderConfigProperty(TenantResolverMapper.CONFIG_REGISTRY_FILE, "Registry file",
                    "Path to the tenant registry JSON (falls back to env TENANT_REGISTRY_FILE, then " + Registries.DEFAULT_REGISTRY_FILE + ").",
                    ProviderConfigProperty.STRING_TYPE, null));

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getDisplayType() {
        return "Tenant guard (refuse tokens for inactive tenants)";
    }

    @Override
    public String getHelpText() {
        return "Re-checks the tenant registry on every token issuance, including refresh, and refuses to issue a token "
                + "when the user's tenant is unknown, suspended or has SSO disabled. Adds no claim.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG;
    }

    // Keycloak's base class only calls setClaim() when the mapper is flagged "include in access token" / "include in ID
    // token". A security check must not depend on a display flag (an admin unticking it would silently disable the
    // guard; the first version of this class had exactly that bug), so both token hooks are overridden to always check.
    @Override
    public AccessToken transformAccessToken(AccessToken token, ProtocolMapperModel mappingModel, KeycloakSession session,
                                            UserSessionModel userSession, ClientSessionContext clientSessionCtx) {
        check(mappingModel, userSession);
        return token;
    }

    @Override
    public IDToken transformIDToken(IDToken token, ProtocolMapperModel mappingModel, KeycloakSession session,
                                    UserSessionModel userSession, ClientSessionContext clientSessionCtx) {
        check(mappingModel, userSession);
        return token;
    }

    private void check(ProtocolMapperModel mappingModel, UserSessionModel userSession) {
        UserModel user = userSession.getUser();
        String tenantId = user.getFirstAttribute(TenantResolverMapper.ATTR_TENANT_ID);
        String registryPath = mappingModel.getConfig() == null ? null : mappingModel.getConfig().get(TenantResolverMapper.CONFIG_REGISTRY_FILE);

        Optional<Tenant> tenant = Registries.forConfiguredPath(registryPath).lookupTenant(tenantId);
        String refusal = null;
        if (tenantId == null || tenantId.isBlank()) {
            refusal = "NO_TENANT_ATTRIBUTE";
        } else if (tenant.isEmpty()) {
            refusal = "UNKNOWN_TENANT";
        } else if (!tenant.get().active()) {
            refusal = "TENANT_SUSPENDED";
        } else if (!tenant.get().ssoEnabled()) {
            refusal = "SSO_DISABLED";
        }

        if (refusal != null) {
            LOG.warnf("TENANT_TOKEN_REFUSED reason=%s tenant=%s user=%s", refusal, tenantId, user.getId());
            throw new ErrorResponseException("invalid_grant", "The tenant is not active", Response.Status.BAD_REQUEST);
        }
    }
}
