package com.secufusion.oidcpoc.tenant;

import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class TenantApiExceptionHandler {

    /** Reaching tenant data without a tenant is a bug or an attack; refuse rather than guess. */
    @ExceptionHandler(TenantContextHolder.MissingTenantContextException.class)
    public ResponseEntity<Map<String, String>> missingTenant() {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("error", "no_tenant_context"));
    }
}
