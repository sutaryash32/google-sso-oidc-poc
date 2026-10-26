package com.secufusion.oidcpoc.config;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * Finds files that live in a sibling project folder (for example google-oidc-poc-keycloak/tenant-registry.json)
 * regardless of the directory the launcher started the backend in.
 *
 * Different launchers use different working directories: Maven runs from google-oidc-poc-backend/, and an IDE run
 * configuration often starts in whatever folder the IDE project was opened at, which can be the repository root OR the
 * folder that contains it. A single relative path cannot be right for all of them, so a relative path is tried:
 *   1. against the working directory and then up to three of its parents, and for each of those
 *   2. against each of that directory's immediate subdirectories (the repository one level down).
 * Nearest wins; at the same level subdirectories are tried in name order so the result is deterministic.
 * An absolute path is used as is.
 */
public final class RepoPaths {

    private static final int MAX_LEVELS_UP = 3;

    private RepoPaths() {
    }

    public static Optional<Path> find(String path) {
        return find(path, Path.of("").toAbsolutePath());
    }

    public static Optional<Path> find(String path, Path startDir) {
        if (path == null || path.isBlank()) {
            return Optional.empty();
        }
        Path wanted = Path.of(path);
        if (wanted.isAbsolute()) {
            return Files.exists(wanted) ? Optional.of(wanted.normalize()) : Optional.empty();
        }
        Path base = startDir.toAbsolutePath();
        for (int level = 0; level <= MAX_LEVELS_UP && base != null; level++, base = base.getParent()) {
            Path direct = base.resolve(wanted).normalize();
            if (Files.exists(direct)) {
                return Optional.of(direct);
            }
            Optional<Path> below = inImmediateSubdirectory(base, wanted);
            if (below.isPresent()) {
                return below;
            }
        }
        return Optional.empty();
    }

    private static Optional<Path> inImmediateSubdirectory(Path base, Path wanted) {
        try (Stream<Path> children = Files.list(base)) {
            return children
                    .filter(Files::isDirectory)
                    .sorted()
                    .map(dir -> dir.resolve(wanted).normalize())
                    .filter(Files::exists)
                    .findFirst();
        } catch (IOException e) {
            return Optional.empty();
        }
    }
}
