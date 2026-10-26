package com.secufusion.oidcpoc.tenant;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** The backend must not trust an old snapshot forever either: a suspension made while the registry is unreachable has to count. */
class FileTenantDirectoryStalenessTest {

    @TempDir
    Path dir;

    private static final String JSON = """
            {"tenants":[{"tenantId":"t-acme","name":"Acme","status":"active","ssoEnabled":true,"domains":["acme.com"]}]}""";
    private static final Duration MAX = Duration.ofMinutes(10);
    private final AtomicLong clock = new AtomicLong(5_000_000);

    private Path write(String json) throws Exception {
        Path f = dir.resolve("registry.json");
        Files.writeString(f, json);
        return f;
    }

    @Test
    void anUnchangedReadableFileStaysTrustedHoweverMuchTimePasses() throws Exception {
        FileTenantDirectory d = new FileTenantDirectory(write(JSON), MAX, clock::get);
        for (int i = 0; i < 4; i++) {
            clock.addAndGet(MAX.toMillis() * 3);
            assertTrue(d.findByTenantId("t-acme").isPresent());
        }
    }

    @Test
    void anUnreadableFileIsServedFromTheSnapshotOnlyUntilItGoesStale() throws Exception {
        Path f = write(JSON);
        FileTenantDirectory d = new FileTenantDirectory(f, MAX, clock::get);
        Files.delete(f);

        clock.addAndGet(MAX.toMillis() - 1_000);
        assertTrue(d.findByTenantId("t-acme").isPresent(), "within the bound the snapshot is still served");

        clock.addAndGet(2_000);
        assertTrue(d.findByTenantId("t-acme").isEmpty(), "past the bound every tenant is unknown");
    }

    @Test
    void aCorruptReplacementIsNotTrustedForeverEither() throws Exception {
        Path f = write(JSON);
        FileTenantDirectory d = new FileTenantDirectory(f, MAX, clock::get);
        Files.writeString(f, "{ not json");
        Files.setLastModifiedTime(f, FileTime.fromMillis(System.currentTimeMillis() + 5_000));
        assertTrue(d.findByTenantId("t-acme").isPresent());

        clock.addAndGet(MAX.toMillis() + 1_000);
        assertTrue(d.findByTenantId("t-acme").isEmpty());
    }

    @Test
    void recoveryRestoresTrustAndReflectsTheCurrentFile() throws Exception {
        Path f = write(JSON);
        FileTenantDirectory d = new FileTenantDirectory(f, MAX, clock::get);
        Files.delete(f);
        clock.addAndGet(MAX.toMillis() + 1_000);
        assertTrue(d.findByTenantId("t-acme").isEmpty());

        write(JSON.replace("\"active\"", "\"suspended\""));
        Files.setLastModifiedTime(f, FileTime.fromMillis(System.currentTimeMillis() + 5_000));
        TenantInfo after = d.findByTenantId("t-acme").orElseThrow();
        assertFalse(after.active(), "it reflects what the file says now, not the old snapshot");
    }

    @Test
    void aRegistryThatNeverLoadedKnowsNoTenant() {
        FileTenantDirectory d = new FileTenantDirectory(dir.resolve("never.json"), MAX, clock::get);
        assertTrue(d.findByTenantId("t-acme").isEmpty());
    }
}
