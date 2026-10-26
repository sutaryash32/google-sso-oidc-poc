package com.secufusion.oidcpoc.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Wires the Google Directory client factory. Clients are created per delegated admin (one per tenant)
 * and only on first use, so the application starts without the service-account key present.
 */
@Configuration
@EnableConfigurationProperties(GoogleWorkspaceProperties.class)
public class GoogleDirectoryClientConfig {

    @Bean
    public DirectoryClientFactory directoryClientFactory(GoogleWorkspaceProperties properties) {
        return new DirectoryClientFactory(properties);
    }
}
