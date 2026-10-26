package com.secufusion.oidcpoc.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class RepoPathsTest {

    @TempDir
    Path root;

    private Path layout() throws Exception {
        Files.createDirectories(root.resolve("google-oidc-poc-keycloak"));
        Files.createDirectories(root.resolve("google-oidc-poc-backend"));
        Files.writeString(root.resolve("google-oidc-poc-keycloak/docker-compose.yml"), "services: {}");
        return root;
    }

    @Test
    void foundFromTheRepoRoot() throws Exception {
        layout();
        assertEquals(root.resolve("google-oidc-poc-keycloak/docker-compose.yml").normalize(),
                RepoPaths.find("google-oidc-poc-keycloak/docker-compose.yml", root).orElseThrow());
    }

    @Test
    void foundFromTheBackendFolderByLookingAtParents() throws Exception {
        layout();
        assertEquals(root.resolve("google-oidc-poc-keycloak/docker-compose.yml").normalize(),
                RepoPaths.find("google-oidc-poc-keycloak/docker-compose.yml", root.resolve("google-oidc-poc-backend")).orElseThrow());
    }

    @Test
    void parentRelativePathsStillWork() throws Exception {
        layout();
        assertTrue(RepoPaths.find("../google-oidc-poc-keycloak/docker-compose.yml", root.resolve("google-oidc-poc-backend")).isPresent());
    }

    @Test
    void absolutePathsAreUsedAsIs() throws Exception {
        layout();
        Path file = root.resolve("google-oidc-poc-keycloak/docker-compose.yml");
        assertEquals(file.normalize(), RepoPaths.find(file.toString(), Path.of("/unrelated")).orElseThrow());
        assertTrue(RepoPaths.find(root.resolve("missing.yml").toString(), root).isEmpty());
    }

    @Test
    void missingOrBlankReturnsEmpty() throws Exception {
        layout();
        assertTrue(RepoPaths.find("google-oidc-poc-keycloak/nope.yml", root).isEmpty());
        assertTrue(RepoPaths.find("", root).isEmpty());
        assertTrue(RepoPaths.find(null, root).isEmpty());
    }

    @Test
    void foundFromTheFolderAboveTheRepository() throws Exception {
        // An IDE project opened at the folder that CONTAINS the repository: C:\...\google-oidc-poc\ holding google-oidc-poc\.
        Path outer = Files.createDirectories(root.resolve("outer"));
        Path inner = Files.createDirectories(outer.resolve("google-oidc-poc/google-oidc-poc-keycloak"));
        Files.writeString(inner.resolve("docker-compose.yml"), "services: {}");
        assertEquals(inner.resolve("docker-compose.yml").normalize(),
                RepoPaths.find("google-oidc-poc-keycloak/docker-compose.yml", outer).orElseThrow());
    }

    @Test
    void doesNotSearchMoreThanOneLevelDown() throws Exception {
        Path outer = Files.createDirectories(root.resolve("outer"));
        Path tooDeep = Files.createDirectories(outer.resolve("x/y/google-oidc-poc-keycloak"));
        Files.writeString(tooDeep.resolve("docker-compose.yml"), "services: {}");
        assertTrue(RepoPaths.find("google-oidc-poc-keycloak/docker-compose.yml", outer).isEmpty());
    }

    @Test
    void whenSeveralSubdirectoriesMatchTheChoiceIsDeterministicByName() throws Exception {
        Path outer = Files.createDirectories(root.resolve("outer"));
        for (String name : new String[]{"b-copy", "a-copy"}) {
            Path dir = Files.createDirectories(outer.resolve(name + "/google-oidc-poc-keycloak"));
            Files.writeString(dir.resolve("docker-compose.yml"), "services: {}");
        }
        assertEquals(outer.resolve("a-copy/google-oidc-poc-keycloak/docker-compose.yml").normalize(),
                RepoPaths.find("google-oidc-poc-keycloak/docker-compose.yml", outer).orElseThrow());
    }

    @Test
    void doesNotSearchMoreThanThreeLevelsUp() throws Exception {
        layout();
        Path deep = Files.createDirectories(root.resolve("a/b/c/d/e"));
        assertTrue(RepoPaths.find("google-oidc-poc-keycloak/docker-compose.yml", deep).isEmpty());
    }
}
