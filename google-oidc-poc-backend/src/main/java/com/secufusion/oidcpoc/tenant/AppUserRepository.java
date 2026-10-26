package com.secufusion.oidcpoc.tenant;

import java.util.UUID;
import org.springframework.stereotype.Repository;

/**
 * Users are keyed by (tenant_id, idp_alias, idp_subject): the provider's own subject for the person, never the email
 * and never the Keycloak user id. Email is a mutable attribute refreshed on every call, so a rename does not create a
 * second identity and a reused address cannot inherit a previous holder's data; and because the Keycloak user id is not
 * part of the key, deleting and re-linking the Keycloak user does not turn a person into a stranger.
 */
@Repository
public class AppUserRepository {

    private final TenantTx tenantTx;

    public AppUserRepository(TenantTx tenantTx) {
        this.tenantTx = tenantTx;
    }

    /** Creates the user on first sight, otherwise refreshes the email; returns the internal user id. */
    public UUID ensureUser() {
        TenantContext ctx = TenantContextHolder.require();
        return tenantTx.run(jdbc -> jdbc.queryForObject("""
                insert into app_user (tenant_id, idp_alias, idp_subject, email)
                values (?, ?, ?, ?)
                on conflict (tenant_id, idp_alias, idp_subject) do update set email = excluded.email
                returning user_id
                """, UUID.class, ctx.tenantId(), ctx.idpAlias(), ctx.idpSubject(), ctx.email()));
    }
}
