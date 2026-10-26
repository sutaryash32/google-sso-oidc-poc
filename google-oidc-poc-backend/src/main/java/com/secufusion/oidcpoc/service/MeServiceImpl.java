package com.secufusion.oidcpoc.service;

import com.secufusion.oidcpoc.dto.UserInfoDTO;
import java.util.List;
import java.util.Map;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;

@Service
public class MeServiceImpl implements MeService {

    @Override
    @SuppressWarnings("unchecked")
    public UserInfoDTO buildUserInfo(Jwt jwt) {
        Map<String, Object> realmAccess = jwt.getClaim("realm_access");
        List<String> roles = realmAccess != null
                ? (List<String>) realmAccess.getOrDefault("roles", List.of())
                : List.of();

        return new UserInfoDTO(
                jwt.getSubject(),
                jwt.getClaimAsString("email"),
                jwt.getClaimAsString("name"),
                jwt.getClaimAsString("preferred_username"),
                identityProvider(jwt),
                roles,
                jwt.getClaims()
        );
    }

    /**
     * The identity provider the user signed in through. Tokens carry it as "idp" (stamped by the tenant plugin, together
     * with the provider's subject). "identity_provider" is the claim name the original single-domain POC used; it is kept
     * as a fallback so older tokens still display something.
     */
    private static String identityProvider(Jwt jwt) {
        String idp = jwt.getClaimAsString("idp");
        return idp != null && !idp.isBlank() ? idp : jwt.getClaimAsString("identity_provider");
    }

    @Override
    public Map<String, Object> getAllClaims(Jwt jwt) {
        return jwt.getClaims();
    }
}
