package com.secufusion.oidcpoc.config;

import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.services.directory.Directory;
import com.google.api.services.directory.DirectoryScopes;
import com.google.auth.http.HttpCredentialsAdapter;
import com.google.auth.oauth2.ServiceAccountCredentials;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;

/**
 * Builds Admin SDK Directory clients that use ONE service account (domain-wide delegation) and
 * impersonate a per-tenant admin. The key is read on first use, and clients are cached per admin.
 *
 * Callers must only pass a delegated admin taken from the tenant registry for the token's tenant,
 * and only for an admin whose domain belongs to that tenant.
 */
public class DirectoryClientFactory {

    private static final List<String> SCOPES = List.of(
            DirectoryScopes.ADMIN_DIRECTORY_GROUP_READONLY,
            DirectoryScopes.ADMIN_DIRECTORY_USER_READONLY);

    private final GoogleWorkspaceProperties properties;
    private final Map<String, Directory> byAdmin = new ConcurrentHashMap<>();
    private volatile ServiceAccountCredentials baseCredentials;

    public DirectoryClientFactory(GoogleWorkspaceProperties properties) {
        this.properties = properties;
    }

    public Directory forDelegatedAdmin(String adminEmail) throws IOException, GeneralSecurityException {
        String key = adminEmail.trim().toLowerCase(Locale.ROOT);
        Directory existing = byAdmin.get(key);
        if (existing != null) {
            return existing;
        }
        HttpTransport transport = new NetHttpTransport();
        Directory built = new Directory.Builder(
                transport,
                GsonFactory.getDefaultInstance(),
                new HttpCredentialsAdapter(base().createScoped(SCOPES).createDelegated(key)))
                .setApplicationName("Google OIDC POC")
                .build();
        byAdmin.put(key, built);
        return built;
    }

    private ServiceAccountCredentials base() throws IOException {
        ServiceAccountCredentials local = baseCredentials;
        if (local == null) {
            synchronized (this) {
                if (baseCredentials == null) {
                    Resource keyResource = new DefaultResourceLoader().getResource(properties.getServiceAccountKeyPath());
                    try (InputStream in = keyResource.getInputStream()) {
                        baseCredentials = (ServiceAccountCredentials) ServiceAccountCredentials.fromStream(in);
                    }
                }
                local = baseCredentials;
            }
        }
        return local;
    }
}
