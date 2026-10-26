package com.secufusion.spike.tenant;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The registry must never serve an old snapshot indefinitely: a suspension made while it is unreachable has to count. */
class FileTenantRegistryStalenessTest {

    @TempDir
    Path dir;

    private static final String ONE_TENANT = """
            {"tenants":[{"tenantId":"t-acme","name":"Acme","status":"active","ssoEnabled":true,"domains":["acme.com"]}]}""";

    private final AtomicLong clock = new AtomicLong(1_000_000);
    private static final Duration MAX = Duration.ofMinutes(10);

    private Path write(String json) throws Exception {
        Path f = dir.resolve("registry.json");
        Files.writeString(f, json);
        return f;
    }

    private static void touchLater(Path f) throws Exception {
        Files.setLastModifiedTime(f, FileTime.fromMillis(System.currentTimeMillis() + 5_000));
    }

    @Test
    void lookupByTenantIdFindsTheTenant() throws Exception {
        FileTenantRegistry r = new FileTenantRegistry(write(ONE_TENANT), MAX, clock::get);
        assertEquals("Acme", r.lookupTenant("t-acme").orElseThrow().name());
        assertTrue(r.lookupTenant("t-missing").isEmpty());
        assertTrue(r.lookupTenant(null).isEmpty());
    }

    @Test
    void anUnchangedReadableFileStaysTrustedNoMatterHowMuchTimePasses() throws Exception {
        FileTenantRegistry r = new FileTenantRegistry(write(ONE_TENANT), MAX, clock::get);
        for (int i = 0; i < 5; i++) {
            clock.addAndGet(MAX.toMillis() * 3); // far longer than the bound, but every call re-checks the file
            assertEquals(TenantRegistry.Kind.FOUND, r.lookupDomain("acme.com").kind());
        }
    }

    @Test
    void anUnreadableFileIsServedFromTheSnapshotOnlyUntilItGoesStale() throws Exception {
        Path f = write(ONE_TENANT);
        FileTenantRegistry r = new FileTenantRegistry(f, MAX, clock::get);
        assertEquals(TenantRegistry.Kind.FOUND, r.lookupDomain("acme.com").kind());

        Files.delete(f); // the registry becomes unreachable

        clock.addAndGet(MAX.toMillis() - 1_000);
        assertEquals(TenantRegistry.Kind.FOUND, r.lookupDomain("acme.com").kind(), "within the bound the snapshot is still served");
        assertTrue(r.lookupTenant("t-acme").isPresent());

        clock.addAndGet(2_000);
        assertEquals(TenantRegistry.Kind.NOT_FOUND, r.lookupDomain("acme.com").kind(), "past the bound everything is denied");
        assertTrue(r.lookupTenant("t-acme").isEmpty());
    }

    @Test
    void aCorruptReplacementIsNotTrustedForeverEither() throws Exception {
        Path f = write(ONE_TENANT);
        FileTenantRegistry r = new FileTenantRegistry(f, MAX, clock::get);

        Files.writeString(f, "{ not json");
        touchLater(f);
        assertEquals(TenantRegistry.Kind.FOUND, r.lookupDomain("acme.com").kind(), "briefly served from the last good snapshot");

        clock.addAndGet(MAX.toMillis() + 1_000);
        assertEquals(TenantRegistry.Kind.NOT_FOUND, r.lookupDomain("acme.com").kind());
    }

    @Test
    void recoveryRestoresTrust() throws Exception {
        Path f = write(ONE_TENANT);
        FileTenantRegistry r = new FileTenantRegistry(f, MAX, clock::get);
        Files.delete(f);
        clock.addAndGet(MAX.toMillis() + 1_000);
        assertEquals(TenantRegistry.Kind.NOT_FOUND, r.lookupDomain("acme.com").kind());

        write(ONE_TENANT.replace("\"active\"", "\"suspended\""));
        touchLater(f);
        TenantRegistry.Lookup after = r.lookupDomain("acme.com");
        assertEquals(TenantRegistry.Kind.FOUND, after.kind());
        assertFalse(after.tenant().active(), "and it reflects what the file says now, not the old snapshot");
    }

    @Test
    void aRegistryThatNeverLoadedDeniesEverything() {
        FileTenantRegistry r = new FileTenantRegistry(dir.resolve("never-existed.json"), MAX, clock::get);
        assertEquals(TenantRegistry.Kind.NOT_FOUND, r.lookupDomain("acme.com").kind());
        assertTrue(r.lookupTenant("t-acme").isEmpty());
    }
}
