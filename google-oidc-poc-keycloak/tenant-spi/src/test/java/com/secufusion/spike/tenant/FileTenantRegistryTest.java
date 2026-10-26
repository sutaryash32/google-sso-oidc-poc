package com.secufusion.spike.tenant;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;

import static org.junit.jupiter.api.Assertions.assertEquals;

class FileTenantRegistryTest {

    @TempDir
    Path dir;

    private Path write(String json) throws Exception {
        Path f = dir.resolve("registry.json");
        Files.writeString(f, json);
        return f;
    }

    private static final String ONE_TENANT = """
            {"tenants":[{"tenantId":"t-acme","name":"Acme","status":"active","ssoEnabled":true,
              "domains":["Acme.com","acme.co.uk."]}]}""";

    @Test
    void normalisesDomainsAndFindsTenant() throws Exception {
        FileTenantRegistry r = new FileTenantRegistry(write(ONE_TENANT));
        assertEquals(TenantRegistry.Kind.FOUND, r.lookupDomain("acme.com").kind());
        assertEquals(TenantRegistry.Kind.FOUND, r.lookupDomain("acme.co.uk").kind());
        assertEquals("t-acme", r.lookupDomain("acme.com").tenant().tenantId());
        assertEquals(TenantRegistry.Kind.NOT_FOUND, r.lookupDomain("other.com").kind());
    }

    @Test
    void duplicateDomainAcrossTenantsIsAmbiguous() throws Exception {
        FileTenantRegistry r = new FileTenantRegistry(write("""
                {"tenants":[
                  {"tenantId":"a","status":"active","ssoEnabled":true,"domains":["dup.com"]},
                  {"tenantId":"b","status":"active","ssoEnabled":true,"domains":["dup.com"]}]}"""));
        assertEquals(TenantRegistry.Kind.AMBIGUOUS, r.lookupDomain("dup.com").kind());
    }

    @Test
    void sameTenantListingDomainTwiceIsNotAmbiguous() throws Exception {
        FileTenantRegistry r = new FileTenantRegistry(write("""
                {"tenants":[{"tenantId":"a","status":"active","ssoEnabled":true,"domains":["x.com","X.com"]}]}"""));
        assertEquals(TenantRegistry.Kind.FOUND, r.lookupDomain("x.com").kind());
    }

    @Test
    void missingFileFailsClosed() {
        FileTenantRegistry r = new FileTenantRegistry(dir.resolve("nope.json"));
        assertEquals(TenantRegistry.Kind.NOT_FOUND, r.lookupDomain("acme.com").kind());
    }

    @Test
    void reloadsWhenFileChanges() throws Exception {
        Path f = write(ONE_TENANT);
        FileTenantRegistry r = new FileTenantRegistry(f);
        assertEquals(TenantRegistry.Kind.FOUND, r.lookupDomain("acme.com").kind());

        Files.writeString(f, """
                {"tenants":[{"tenantId":"t-acme","status":"suspended","ssoEnabled":true,"domains":["acme.com"]}]}""");
        Files.setLastModifiedTime(f, FileTime.fromMillis(System.currentTimeMillis() + 5_000));
        assertEquals(false, r.lookupDomain("acme.com").tenant().active());
    }

    @Test
    void badReloadKeepsLastGoodSnapshot() throws Exception {
        Path f = write(ONE_TENANT);
        FileTenantRegistry r = new FileTenantRegistry(f);
        Files.writeString(f, "{ this is not json");
        Files.setLastModifiedTime(f, FileTime.fromMillis(System.currentTimeMillis() + 5_000));
        assertEquals(TenantRegistry.Kind.FOUND, r.lookupDomain("acme.com").kind());
    }
}
