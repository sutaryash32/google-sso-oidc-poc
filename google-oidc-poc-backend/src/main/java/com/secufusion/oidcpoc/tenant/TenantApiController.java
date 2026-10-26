package com.secufusion.oidcpoc.tenant;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Tenant-scoped endpoints. Nothing here accepts a tenant as input except to compare it with the token's. */
@RestController
@RequestMapping("/api")
public class TenantApiController {

    public record NewDocument(String title, String body) {
    }

    private final AppUserRepository users;
    private final DocumentRepository documents;

    public TenantApiController(AppUserRepository users, DocumentRepository documents) {
        this.users = users;
        this.documents = documents;
    }

    @GetMapping("/tenant/me")
    public Map<String, Object> me() {
        TenantContext ctx = TenantContextHolder.require();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("userId", users.ensureUser());
        out.put("tenantId", ctx.tenantId());
        out.put("tenantDomain", ctx.tenantDomain());
        out.put("subject", ctx.subject());
        out.put("email", ctx.email());
        return out;
    }

    @GetMapping("/documents")
    public List<DocumentRepository.Document> list() {
        return documents.findAll();
    }

    @PostMapping("/documents")
    public ResponseEntity<DocumentRepository.Document> create(@RequestBody NewDocument request) {
        if (request == null || request.title() == null || request.title().isBlank()) {
            return ResponseEntity.badRequest().build();
        }
        UUID createdBy = users.ensureUser();
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(documents.insert(request.title(), request.body(), createdBy));
    }

    @GetMapping("/documents/{id}")
    public ResponseEntity<DocumentRepository.Document> get(@PathVariable String id) {
        UUID uuid;
        try {
            uuid = UUID.fromString(id);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.notFound().build();
        }
        return documents.findById(uuid).map(ResponseEntity::ok).orElseGet(() -> ResponseEntity.notFound().build());
    }

    /**
     * Shows the rule for tenant-in-path URLs: the path value must equal the token's tenant, otherwise
     * the response is 404 (not 403), so the existence of other tenants is not confirmed.
     */
    @GetMapping("/tenants/{tenantId}/documents")
    public ResponseEntity<List<DocumentRepository.Document>> listForTenant(@PathVariable String tenantId) {
        if (!tenantId.equals(TenantContextHolder.require().tenantId())) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(documents.findAll());
    }
}
