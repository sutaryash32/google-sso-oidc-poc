package com.secufusion.oidcpoc.service;

import com.secufusion.oidcpoc.dto.UserInfoDTO;
import java.util.Map;
import org.springframework.security.oauth2.jwt.Jwt;

public interface MeService {

    UserInfoDTO buildUserInfo(Jwt jwt);

    Map<String, Object> getAllClaims(Jwt jwt);
}
