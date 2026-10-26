package com.secufusion.spike.tenant;

import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.broker.AbstractIdpAuthenticator;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * Replaces Keycloak's "Handle Existing Account" step in a copy of the first-broker-login flow.
 *
 * Keycloak reaches it when a new brokered identity (a Google subject Keycloak has never seen) matches an EXISTING user
 * by email. The default flow then offers to link them after "Verify existing account by Email", which lets the new
 * holder of a reused mailbox (a deleted-and-recreated account, or a new hire given a former employee's address) take
 * over the old user and everything keyed to it. We never link by email: the only identity that counts is the
 * provider subject, so this step denies and records why. An administrator resolves it deliberately (for example by
 * deleting the stale user or re-pointing the link).
 */
public class NoEmailLinkAuthenticator implements Authenticator {

    private static final Logger LOG = Logger.getLogger(NoEmailLinkAuthenticator.class);

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        String idp = "?";
        String subject = "?";
        String existing = "?";
        try {
            SerializedBrokeredIdentityContext brokered = SerializedBrokeredIdentityContext.readFromAuthenticationSession(
                    context.getAuthenticationSession(), AbstractIdpAuthenticator.BROKERED_CONTEXT_NOTE);
            if (brokered != null) {
                idp = brokered.getIdentityProviderId();
                subject = brokered.getId();
            }
            String info = context.getAuthenticationSession().getAuthNote(AbstractIdpAuthenticator.EXISTING_USER_INFO);
            if (info != null) {
                existing = info;
            }
        } catch (RuntimeException e) {
            LOG.debugf("Could not read brokered context for the audit line: %s", e.getMessage());
        }
        LOG.warnf("TENANT_DENIED reason=EXISTING_ACCOUNT_NOT_LINKED idp=%s sub=%s existing=%s", idp, subject, existing);
        Response error = context.form().setError("access-denied").createErrorPage(Response.Status.FORBIDDEN);
        context.failure(AuthenticationFlowError.ACCESS_DENIED, error);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        authenticate(context);
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // nothing
    }

    @Override
    public void close() {
        // nothing
    }
}
