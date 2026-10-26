package com.secufusion.spike.tenant;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

public class NoEmailLinkAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "tenant-no-email-link";

    private static final NoEmailLinkAuthenticator SINGLETON = new NoEmailLinkAuthenticator();

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENTS = {
            AuthenticationExecutionModel.Requirement.ALTERNATIVE,
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED};

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Deny existing account (never link by email)";
    }

    @Override
    public String getReferenceCategory() {
        return "tenant";
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENTS;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Refuses to link a new provider identity to an existing user that merely shares its email address.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return List.of();
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public void init(Config.Scope config) {
        // nothing
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // nothing
    }

    @Override
    public void close() {
        // nothing
    }
}
