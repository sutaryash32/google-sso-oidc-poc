package com.secufusion.oidcpoc.tenant;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

/**
 * Example of tenant-owned data. Every statement filters on tenant_id explicitly AND runs inside a
 * {@link TenantTx} so Postgres row-level security enforces the same boundary independently.
 * Lookups by id always include the tenant: "not yours" and "does not exist" are indistinguishable.
 */
@Repository
public class DocumentRepository {

    public record Document(UUID id, String title, String body, UUID createdBy, OffsetDateTime createdAt) {
    }

    private static final RowMapper<Document> MAPPER = (rs, i) -> new Document(
            rs.getObject("id", UUID.class),
            rs.getString("title"),
            rs.getString("body"),
            rs.getObject("created_by", UUID.class),
            rs.getObject("created_at", OffsetDateTime.class));

    private final TenantTx tenantTx;

    public DocumentRepository(TenantTx tenantTx) {
        this.tenantTx = tenantTx;
    }

    public List<Document> findAll() {
        String tenantId = TenantContextHolder.require().tenantId();
        return tenantTx.run(jdbc -> jdbc.query(
                "select id, title, body, created_by, created_at from document where tenant_id = ? order by created_at, id",
                MAPPER, tenantId));
    }

    public Optional<Document> findById(UUID id) {
        String tenantId = TenantContextHolder.require().tenantId();
        return tenantTx.run(jdbc -> jdbc.query(
                "select id, title, body, created_by, created_at from document where tenant_id = ? and id = ?",
                MAPPER, tenantId, id).stream().findFirst());
    }

    public Document insert(String title, String body, UUID createdBy) {
        String tenantId = TenantContextHolder.require().tenantId();
        return tenantTx.run(jdbc -> jdbc.queryForObject("""
                insert into document (tenant_id, title, body, created_by)
                values (?, ?, ?, ?)
                returning id, title, body, created_by, created_at
                """, MAPPER, tenantId, title, body, createdBy));
    }
}
