package com.secufusion.oidcpoc.config;

import java.nio.file.Path;
import java.util.Map;
import java.util.Optional;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;

/**
 * Tells Spring Boot's Docker Compose support where the compose file is, from whatever directory the backend was
 * started in. Without this, {@code spring.docker.compose.file} would need a path that is only right for one
 * launcher (Maven vs an IDE). An explicit {@code spring.docker.compose.file} setting always wins.
 */
public class ComposeFileLocator implements EnvironmentPostProcessor {

    static final String PROPERTY = "spring.docker.compose.file";
    static final String DEFAULT_RELATIVE_PATH = "google-oidc-poc-keycloak/docker-compose.yml";

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
        if (environment.containsProperty(PROPERTY)) {
            return;
        }
        Optional<Path> found = RepoPaths.find(DEFAULT_RELATIVE_PATH);
        found.ifPresent(path -> environment.getPropertySources()
                .addLast(new MapPropertySource("composeFileLocator", Map.of(PROPERTY, path.toString()))));
    }
}
