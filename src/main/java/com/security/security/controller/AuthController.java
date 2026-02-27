package com.security.security.controller;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.security.security.service.AuthService;

import jakarta.servlet.http.HttpServletResponse;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {
    @Autowired
    private AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@RequestBody Map<String, String> userData,
            HttpServletResponse response) {
        try {
            Map<String, Object> map = authService.registerUser(userData);
            ResponseCookie cookie = (ResponseCookie) map.get("cookie");
            response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
            String token = (String) map.get("accessToken");
            return ResponseEntity.ok().body(token);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("There is an Error : " + e.getMessage());
        }
    }
    @PostMapping("/login")
    public ResponseEntity<String> loginUser(@RequestBody Map<String, String> loginData,
            HttpServletResponse response) {
        try {
            Map<String, Object> map = authService.loginUser(loginData);
            ResponseCookie cookie = (ResponseCookie) map.get("cookie");
            response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
            String token = (String) map.get("accessToken");
            return ResponseEntity.ok().body(token);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("There is an Error : " + e.getMessage());
        }

    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(
            @CookieValue(name = "refreshToken") String refreshToken) {
        try {
            if (refreshToken == null)
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();

            return ResponseEntity.ok()
                    .header(HttpHeaders.CACHE_CONTROL, "no-store, no-cache, must-revalidate")
                    .header(HttpHeaders.PRAGMA, "no-cache")
                    .header(HttpHeaders.EXPIRES, "0")
                    .body(authService.refresh(refreshToken));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }

    }
}

