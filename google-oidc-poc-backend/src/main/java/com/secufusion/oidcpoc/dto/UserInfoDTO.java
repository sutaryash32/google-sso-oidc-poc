package com.secufusion.oidcpoc.dto;

import java.util.List;
import java.util.Map;

public record UserInfoDTO(
        String sub,
        String email,
        String name,
        String preferredUsername,
        String identityProvider,
        List<String> roles,
        Map<String, Object> allClaims
) {}
