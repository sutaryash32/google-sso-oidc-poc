package com.secufusion.oidcpoc.tenant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class FileTenantDirectoryTest {

    @TempDir
    Path dir;

    private static final String JSON = """
            {"tenants":[
              {"tenantId":"t-acme","name":"Acme","status":"active","ssoEnabled":true,"domains":["Acme.com","acme.co.uk"]},
              {"tenantId":"t-initech","name":"Initech","status":"suspended","ssoEnabled":true,"domains":["initech.com"]}]}""";

    private Path write(String json) throws Exception {
        Path f = dir.resolve("registry.json");
        Files.writeString(f, json);
        return f;
    }

    @Test
    void parsesTenantsAndNormalisesDomains() throws Exception {
        FileTenantDirectory d = new FileTenantDirectory(write(JSON));
        TenantInfo acme = d.findByTenantId("t-acme").orElseThrow();
        assertTrue(acme.active());
        assertTrue(acme.domains().contains("acme.com"));
        assertFalse(d.findByTenantId("t-initech").orElseThrow().active());
        assertTrue(d.findByTenantId("t-missing").isEmpty());
        assertTrue(d.findByTenantId(null).isEmpty());
    }

    @Test
    void readsTheOptionalPerTenantGroupsDelegatedAdmin() throws Exception {
        FileTenantDirectory d = new FileTenantDirectory(write("""
                {"tenants":[
                  {"tenantId":"a","status":"active","ssoEnabled":true,"domains":["a.com"],"groupsDelegatedAdmin":" Admin@A.com "},
                  {"tenantId":"b","status":"active","ssoEnabled":true,"domains":["b.com"]},
                  {"tenantId":"c","status":"active","ssoEnabled":true,"domains":["c.com"],"groupsDelegatedAdmin":""}]}"""));
        assertEquals("admin@a.com", d.findByTenantId("a").orElseThrow().groupsDelegatedAdmin());
        assertEquals(null, d.findByTenantId("b").orElseThrow().groupsDelegatedAdmin());
        assertEquals(null, d.findByTenantId("c").orElseThrow().groupsDelegatedAdmin());
    }

    @Test
    void missingFileFailsClosed() {
        FileTenantDirectory d = new FileTenantDirectory(dir.resolve("nope.json"));
        assertTrue(d.findByTenantId("t-acme").isEmpty());
    }

    @Test
    void reloadsWhenTheFileChanges() throws Exception {
        Path f = write(JSON);
        FileTenantDirectory d = new FileTenantDirectory(f);
        assertTrue(d.findByTenantId("t-acme").orElseThrow().active());

        Files.writeString(f, JSON.replace("\"t-acme\",\"name\":\"Acme\",\"status\":\"active\"",
                "\"t-acme\",\"name\":\"Acme\",\"status\":\"suspended\""));
        Files.setLastModifiedTime(f, FileTime.fromMillis(System.currentTimeMillis() + 5_000));
        assertFalse(d.findByTenantId("t-acme").orElseThrow().active());
    }

    @Test
    void badReloadKeepsTheLastGoodSnapshot() throws Exception {
        Path f = write(JSON);
        FileTenantDirectory d = new FileTenantDirectory(f);
        Files.writeString(f, "{ not json");
        Files.setLastModifiedTime(f, FileTime.fromMillis(System.currentTimeMillis() + 5_000));
        assertEquals("t-acme", d.findByTenantId("t-acme").orElseThrow().tenantId());
    }
}
