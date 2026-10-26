package com.secufusion.oidcpoc.service;

import com.google.api.client.googleapis.json.GoogleJsonResponseException;
import com.google.api.services.directory.Directory;
import com.google.api.services.directory.model.Group;
import com.google.api.services.directory.model.Groups;
import com.secufusion.oidcpoc.config.DirectoryClientFactory;
import com.secufusion.oidcpoc.dto.UserGroupsResponse;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Post-login group fetch — this is what replaces the missing OIDC groups claim. The delegated admin is
 * supplied by the caller from the tenant registry (one per tenant), never from request input.
 */
@Service
public class GoogleGroupsService {

    private static final Logger log = LoggerFactory.getLogger(GoogleGroupsService.class);

    private final DirectoryClientFactory directoryClients;

    public GoogleGroupsService(DirectoryClientFactory directoryClients) {
        this.directoryClients = directoryClients;
    }

    public UserGroupsResponse fetchGroupsForUser(String delegatedAdmin, String userEmail) {
        log.info("Fetching Google groups for user: {} (via delegated admin {})", userEmail, delegatedAdmin);
        try {
            Directory directory = directoryClients.forDelegatedAdmin(delegatedAdmin);
            Groups result = directory.groups()
                    .list()
                    .setUserKey(userEmail)
                    .execute();

            List<Group> groupList = result.getGroups();
            if (groupList == null) {
                groupList = List.of();
            }

            List<UserGroupsResponse.GroupInfo> groups = groupList.stream()
                    .map(g -> new UserGroupsResponse.GroupInfo(g.getId(), g.getEmail(), g.getName()))
                    .collect(Collectors.toList());

            log.info("Successfully fetched {} groups for user: {}", groups.size(), userEmail);
            return new UserGroupsResponse(userEmail, groups);

        } catch (GoogleJsonResponseException e) {
            log.error("Google API error for user {}: status={}, details={}",
                    userEmail, e.getStatusCode(), e.getDetails(), e);
            throw new GoogleGroupsFetchException(
                    "Google API error for " + userEmail + ": " + e.getDetails().getMessage(), e);
        } catch (IOException | GeneralSecurityException e) {
            log.error("Error fetching Google groups for user {}: {}", userEmail, e.getMessage(), e);
            throw new GoogleGroupsFetchException(
                    "Could not fetch groups for " + userEmail + " from Google Directory API", e);
        }
    }

    public static class GoogleGroupsFetchException extends RuntimeException {
        public GoogleGroupsFetchException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
