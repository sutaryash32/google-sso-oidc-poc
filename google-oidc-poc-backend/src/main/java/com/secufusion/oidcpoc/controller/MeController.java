package com.secufusion.oidcpoc.controller;

import com.secufusion.oidcpoc.dto.UserInfoDTO;
import com.secufusion.oidcpoc.service.MeService;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class MeController {

    private final MeService meService;

    public MeController(MeService meService) {
        this.meService = meService;
    }

    @GetMapping("/public")
    public ResponseEntity<String> publicEndpoint() {
        return ResponseEntity.ok("App is running. No auth needed here.");
    }

    @GetMapping("/me")
    public ResponseEntity<UserInfoDTO> me(@AuthenticationPrincipal Jwt jwt) {
        return ResponseEntity.ok(meService.buildUserInfo(jwt));
    }

    @GetMapping("/token-debug")
    public ResponseEntity<Map<String, Object>> tokenDebug(@AuthenticationPrincipal Jwt jwt) {
        return ResponseEntity.ok(meService.getAllClaims(jwt));
    }
}
