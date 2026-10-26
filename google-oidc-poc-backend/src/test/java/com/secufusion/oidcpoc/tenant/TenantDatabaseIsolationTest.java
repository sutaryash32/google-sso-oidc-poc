package com.secufusion.oidcpoc.tenant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.Connection;
import java.sql.DriverManager;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Exercises the real Postgres row-level-security schema (google-oidc-poc-keycloak/db/init.sql) as the
 * application role. Skipped automatically when the spike database is not running.
 *
 * DESTRUCTIVE: it truncates document_comment, document and app_user. It therefore only runs against the
 * disposable spike database (URL ending in /spike) unless ALLOW_DESTRUCTIVE_DB_TESTS=true.
 *
 * Start it with:  docker compose up -d spike-db   (in google-oidc-poc-keycloak/test-harness/)
 */
class TenantDatabaseIsolationTest {

    private static final String URL = env("TENANT_DB_URL", "jdbc:postgresql://localhost:5434/spike");
    private static final String APP_USER = env("TENANT_DB_USER", "app_user");
    private static final String APP_PW = env("TENANT_DB_PASSWORD", "app_pw");
    private static final String OWNER_USER = env("TENANT_DB_OWNER_USER", "spike_owner");
    private static final String OWNER_PW = env("TENANT_DB_OWNER_PASSWORD", "owner_pw");

    private static JdbcTemplate owner; // bypasses RLS: only for setup, cleanup and inspection
    private static TenantTx tenantTx;
    private static AppUserRepository users;
    private static DocumentRepository documents;

    @BeforeAll
    static void connect() {
        // These tests TRUNCATE the tenant tables between cases. Refuse to touch anything that is not the
        // disposable spike database unless that is explicitly requested.
        if (!URL.endsWith("/spike") && !"true".equals(System.getenv("ALLOW_DESTRUCTIVE_DB_TESTS"))) {
            String reason = "refusing to run destructive tests against " + URL
                    + " (set ALLOW_DESTRUCTIVE_DB_TESTS=true to override; only the disposable spike database is allowed by default)";
            System.err.println("SKIPPING TenantDatabaseIsolationTest: " + reason);
            Assumptions.abort(reason);
        }
        try (Connection ignored = DriverManager.getConnection(URL, APP_USER, APP_PW)) {
            // reachable
        } catch (Exception e) {
            String reason = "spike database not reachable at " + URL + " (" + e + ")";
            System.err.println("SKIPPING TenantDatabaseIsolationTest: " + reason);
            Assumptions.abort(reason);
        }
        owner = new JdbcTemplate(new DriverManagerDataSource(URL, OWNER_USER, OWNER_PW));
        DriverManagerDataSource appDs = new DriverManagerDataSource(URL, APP_USER, APP_PW);
        tenantTx = new TenantTx(new JdbcTemplate(appDs), new TransactionTemplate(new DataSourceTransactionManager(appDs)));
        users = new AppUserRepository(tenantTx);
        documents = new DocumentRepository(tenantTx);
    }

    @BeforeEach
    @AfterEach
    void wipe() {
        if (owner != null) {
            owner.execute("truncate document_comment, document, app_user");
        }
        TenantContextHolder.clear();
    }

    private static void actAs(String tenantId, String subject, String email) {
        // `subject` is the PROVIDER subject (the person key); the Keycloak user id is deliberately unrelated to it.
        TenantContextHolder.set(new TenantContext(tenantId, tenantId.substring(2) + ".com", "kc-" + UUID.randomUUID(), "google", subject, email));
    }

    private static UUID createDocFor(String tenantId, String subject, String title) {
        actAs(tenantId, subject, subject + "@" + tenantId.substring(2) + ".com");
        return documents.insert(title, "body", users.ensureUser()).id();
    }

    // ---- the application role must not be able to sidestep RLS ----

    @Test
    void applicationRoleIsNeitherSuperuserNorBypassRlsAndTablesForceRls() {
        Map<String, Object> role = new JdbcTemplate(new DriverManagerDataSource(URL, APP_USER, APP_PW))
                .queryForMap("select rolsuper, rolbypassrls from pg_roles where rolname = current_user");
        assertEquals(false, role.get("rolsuper"));
        assertEquals(false, role.get("rolbypassrls"));

        List<Map<String, Object>> tables = owner.queryForList(
                "select relname, relrowsecurity, relforcerowsecurity from pg_class "
                        + "where relname in ('app_user','document','document_comment') and relkind = 'r'");
        assertEquals(3, tables.size());
        for (Map<String, Object> t : tables) {
            assertEquals(true, t.get("relrowsecurity"), t.get("relname") + " must have RLS enabled");
            assertEquals(true, t.get("relforcerowsecurity"), t.get("relname") + " must FORCE RLS");
        }
    }

    // ---- RLS as the second layer ----

    @Test
    void aQueryWithNoTenantPredicateStillOnlySeesTheCurrentTenantsRows() {
        createDocFor("t-acme", "alice", "acme doc");
        createDocFor("t-globex", "bob", "globex doc");

        // Deliberately "forgets" the WHERE tenant_id clause.
        Integer asAcme = tenantTx.runAs("t-acme", jdbc -> jdbc.queryForObject("select count(*) from document", Integer.class));
        Integer asGlobex = tenantTx.runAs("t-globex", jdbc -> jdbc.queryForObject("select count(*) from document", Integer.class));
        Integer total = owner.queryForObject("select count(*) from document", Integer.class);

        assertEquals(1, asAcme);
        assertEquals(1, asGlobex);
        assertEquals(2, total);
    }

    @Test
    void aSessionWithNoTenantBoundSeesNothing() {
        createDocFor("t-acme", "alice", "acme doc");
        JdbcTemplate fresh = new JdbcTemplate(new DriverManagerDataSource(URL, APP_USER, APP_PW));
        assertEquals(0, fresh.queryForObject("select count(*) from document", Integer.class));
        assertEquals(0, fresh.queryForObject("select count(*) from app_user", Integer.class));
    }

    @Test
    void anEmptyTenantMatchesNothing() {
        createDocFor("t-acme", "alice", "acme doc");
        Integer n = tenantTx.runAs("", jdbc -> jdbc.queryForObject("select count(*) from document", Integer.class));
        assertEquals(0, n);
    }

    @Test
    void theTenantBindingDoesNotLeakToTheNextUseOfTheSameConnection() {
        createDocFor("t-acme", "alice", "acme doc");
        // One physical connection reused for both calls, like a pooled connection.
        SingleConnectionDataSource one = new SingleConnectionDataSource(URL, APP_USER, APP_PW, true);
        try {
            JdbcTemplate jdbc = new JdbcTemplate(one);
            TenantTx tx = new TenantTx(jdbc, new TransactionTemplate(new DataSourceTransactionManager(one)));
            Integer inTenantTx = tx.runAs("t-acme", j -> j.queryForObject("select count(*) from document", Integer.class));
            // Same connection, outside any tenant transaction: must see nothing.
            Integer afterwards = jdbc.queryForObject("select count(*) from document", Integer.class);
            assertEquals(1, inTenantTx);
            assertEquals(0, afterwards);
        } finally {
            one.destroy();
        }
    }

    @Test
    void writingARowForAnotherTenantIsBlockedByTheWithCheckPolicy() {
        DataAccessException e = assertThrows(DataAccessException.class, () ->
                tenantTx.runAs("t-acme", jdbc -> jdbc.update(
                        "insert into document (tenant_id, title) values ('t-globex', 'smuggled')")));
        // Spring hides the driver's text behind "bad SQL grammar"; the root cause names the policy.
        String root = org.springframework.core.NestedExceptionUtils.getMostSpecificCause(e).getMessage();
        assertTrue(root.toLowerCase().contains("row-level security"), root);
        assertEquals(0, owner.queryForObject("select count(*) from document", Integer.class));
    }

    @Test
    void updatingAndDeletingAnotherTenantsRowAffectsNothing() {
        UUID globexDoc = createDocFor("t-globex", "bob", "globex doc");
        int updated = tenantTx.runAs("t-acme", jdbc -> jdbc.update("update document set title = 'pwned' where id = ?", globexDoc));
        int deleted = tenantTx.runAs("t-acme", jdbc -> jdbc.update("delete from document where id = ?", globexDoc));
        assertEquals(0, updated);
        assertEquals(0, deleted);
        assertEquals("globex doc", owner.queryForObject("select title from document where id = ?", String.class, globexDoc));
    }

    // ---- schema constraints as the first layer ----

    @Test
    void aCommentCannotReferenceAnotherTenantsDocument() {
        UUID globexDoc = createDocFor("t-globex", "bob", "globex doc");
        assertThrows(DataIntegrityViolationException.class, () ->
                tenantTx.runAs("t-acme", jdbc -> jdbc.update(
                        "insert into document_comment (tenant_id, document_id, comment) values ('t-acme', ?, 'hi')", globexDoc)));
    }

    // ---- repositories ----

    @Test
    void repositoryOnlyReturnsAndFindsTheCallersTenantData() {
        UUID acmeDoc = createDocFor("t-acme", "alice", "acme doc");
        createDocFor("t-globex", "bob", "globex doc");

        actAs("t-acme", "alice", "alice@acme.com");
        assertEquals(1, documents.findAll().size());
        assertTrue(documents.findById(acmeDoc).isPresent());

        actAs("t-globex", "bob", "bob@globex.com");
        assertEquals(1, documents.findAll().size());
        assertFalse(documents.findById(acmeDoc).isPresent(), "another tenant's id must look like it does not exist");
    }

    @Test
    void dataAccessWithoutATenantContextFailsClosed() {
        assertThrows(TenantContextHolder.MissingTenantContextException.class, () -> documents.findAll());
        assertThrows(TenantContextHolder.MissingTenantContextException.class, () -> users.ensureUser());
    }

    // ---- identity model ----

    @Test
    void usersAreKeyedByTenantProviderAndProviderSubjectNotEmailNorKeycloakId() {
        actAs("t-acme", "sub-1", "old@acme.com");
        UUID first = users.ensureUser();

        // actAs() gives every call a different, random Keycloak user id, so this also proves that deleting and
        // re-linking the Keycloak user (which changes its id) does not change who the person is.
        actAs("t-acme", "sub-1", "renamed@acme.com"); // same person, email changed, different Keycloak id
        assertEquals(first, users.ensureUser());
        assertEquals("renamed@acme.com", owner.queryForObject(
                "select email from app_user where user_id = ?", String.class, first));

        actAs("t-acme", "sub-2", "renamed@acme.com"); // different subject reusing the address: new identity
        assertNotEquals(first, users.ensureUser());

        actAs("t-globex", "sub-1", "old@acme.com"); // same subject string in another tenant: separate identity
        assertNotEquals(first, users.ensureUser());

        // Same tenant, same subject string, but issued by a different provider: a different person.
        TenantContextHolder.set(new TenantContext("t-acme", "acme.com", "kc-" + UUID.randomUUID(), "okta-acme", "sub-1", "old@acme.com"));
        assertNotEquals(first, users.ensureUser());

        assertEquals(4, owner.queryForObject("select count(*) from app_user", Integer.class));
    }

    private static String env(String name, String fallback) {
        String v = System.getenv(name);
        return v == null || v.isBlank() ? fallback : v;
    }
}
