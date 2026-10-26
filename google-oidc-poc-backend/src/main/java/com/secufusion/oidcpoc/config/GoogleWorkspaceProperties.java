package com.secufusion.oidcpoc.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Google Workspace service-account settings. The delegated admin is NOT configured here: it is per tenant
 * and comes from the tenant registry (groupsDelegatedAdmin).
 */
@ConfigurationProperties(prefix = "google.workspace")
public class GoogleWorkspaceProperties {

    private String serviceAccountKeyPath;
    private String customerId;

    public String getServiceAccountKeyPath() {
        return serviceAccountKeyPath;
    }

    public void setServiceAccountKeyPath(String serviceAccountKeyPath) {
        this.serviceAccountKeyPath = serviceAccountKeyPath;
    }

    public String getCustomerId() {
        return customerId;
    }

    public void setCustomerId(String customerId) {
        this.customerId = customerId;
    }
}
