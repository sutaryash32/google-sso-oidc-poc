-- Tenant-isolation schema for the spike. Runs once, as the database owner (spike_owner).
--
-- Layers of isolation, all of which must hold:
--   1. tenant_id NOT NULL on every tenant-owned table
--   2. composite keys / foreign keys that include tenant_id, so a cross-tenant reference cannot be stored
--   3. row-level security (ENABLE + FORCE) reading the transaction-local setting app.tenant_id
--   4. the application connects as app_user: not the owner, not a superuser, no BYPASSRLS
--      (owners and superusers bypass RLS, which would silently disable layer 3)

CREATE ROLE app_user LOGIN PASSWORD 'app_pw' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;

CREATE TABLE app_user (
    user_id     uuid        NOT NULL DEFAULT gen_random_uuid(),
    tenant_id   text        NOT NULL,
    -- The person key is (tenant_id, idp_alias, idp_subject): the identity provider and ITS subject for the person
    -- (Google "sub"). Not email (mutable, reused) and not the Keycloak user id (changes if the user is re-linked).
    idp_alias   text        NOT NULL,
    idp_subject text        NOT NULL,
    email       text,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, user_id),
    UNIQUE (tenant_id, idp_alias, idp_subject)
);

CREATE TABLE document (
    id          uuid        NOT NULL DEFAULT gen_random_uuid(),
    tenant_id   text        NOT NULL,
    title       text        NOT NULL,
    body        text,
    created_by  uuid,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id, created_by) REFERENCES app_user (tenant_id, user_id)
);

CREATE TABLE document_comment (
    id          uuid NOT NULL DEFAULT gen_random_uuid(),
    tenant_id   text NOT NULL,
    document_id uuid NOT NULL,
    comment     text NOT NULL,
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id, document_id) REFERENCES document (tenant_id, id)
);

GRANT USAGE ON SCHEMA public TO app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON app_user, document, document_comment TO app_user;

-- current_setting(..., true) is NULL when the setting was never set, so "no tenant" matches no rows.
DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['app_user', 'document', 'document_comment'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format($p$CREATE POLICY tenant_isolation ON %I
                          USING (tenant_id = current_setting('app.tenant_id', true))
                          WITH CHECK (tenant_id = current_setting('app.tenant_id', true))$p$, t);
    END LOOP;
END
$$;
