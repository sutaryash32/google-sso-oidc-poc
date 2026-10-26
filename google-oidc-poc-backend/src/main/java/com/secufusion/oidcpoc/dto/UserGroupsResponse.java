package com.secufusion.oidcpoc.dto;

import java.util.List;

public record UserGroupsResponse(
        String userEmail,
        List<GroupInfo> groups
) {
    public record GroupInfo(
            String id,
            String email,
            String name
    ) {}
}
