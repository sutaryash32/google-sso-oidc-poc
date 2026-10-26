package com.secufusion.oidcpoc.tenant;

import java.util.function.Function;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * The only way tenant data is touched. Opens a transaction and binds the tenant to it with
 * {@code set_config('app.tenant_id', ?, true)} (transaction-local, parameterised), which the
 * Postgres row-level-security policies read. Because the setting is transaction-local it cannot
 * leak to the next request that reuses the pooled connection.
 *
 * Repositories additionally filter on tenant_id explicitly; RLS is the second layer, not the first.
 */
@Component
public class TenantTx {

    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;

    public TenantTx(JdbcTemplate jdbc, TransactionTemplate tx) {
        this.jdbc = jdbc;
        this.tx = tx;
    }

    /** Runs as the request's tenant; throws if there is none. */
    public <T> T run(Function<JdbcTemplate, T> work) {
        return runAs(TenantContextHolder.require().tenantId(), work);
    }

    /** Explicit tenant, for background jobs and tests. Never call with a value taken from a request. */
    public <T> T runAs(String tenantId, Function<JdbcTemplate, T> work) {
        return tx.execute(status -> {
            jdbc.queryForObject("select set_config('app.tenant_id', ?, true)", String.class, tenantId);
            return work.apply(jdbc);
        });
    }
}
