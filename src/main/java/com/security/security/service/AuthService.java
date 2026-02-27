package com.security.security.service;

import java.time.Duration;
import java.util.List;
import java.util.Map;

// import org.springframework.security.core.Authentication;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;
import org.springframework.security.authentication.AuthenticationManager;
// import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;

// import com.security.security.config.CustomUserDetails;
import com.security.security.jwts.JWTUtil;
import com.security.security.jwts.RefreshTokenService;
import com.security.security.model.RefreshToken;
import com.security.security.model.Users;
import com.security.security.repository.UserRepository;

@Service
public class AuthService {
    @Autowired
    UserRepository userRepository;
    @Autowired
    PasswordEncoder passwordEncoder;
    @Autowired
    JWTUtil jwtUtil;
    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    RefreshTokenService refreshTokenService;

    public Map<String, Object> registerUser(Map<String, String> userData) {
        String username = userData.get("username");
        String email = userData.get("email");
        String password = userData.get("password");
        String role = userData.get("role");

        if (username == null || username.isBlank())
            throw new RuntimeException("Username is required");
        if (email == null || email.isBlank() || !email.matches("^[A-Za-z0-9+_.-]+@(.+)$"))
            throw new RuntimeException("Invalid email format");
        if (password == null || password.isBlank())
            throw new RuntimeException("Password is required");
        if (!password.matches("^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=!]).{8,}$"))
            throw new RuntimeException("Weak password");
        if (userRepository.existsByEmail(email))
            throw new RuntimeException("Email already registered");
        if (userRepository.existsByUsername(username))
            throw new RuntimeException("Username already taken");
        if (!List.of("USER", "ADMIN").contains(role))
            throw new RuntimeException("Invalid role");

        userRepository.save(Users.builder()
                .username(username)
                .email(email)
                .password(passwordEncoder.encode(password))
                .role(role)
                .isActivated(false)
                .build());

        return loginUser(Map.of("username", username, "password", password));
    }

    public Map<String, Object> loginUser(Map<String, String> loginData) {
        String username = loginData.get("username");
        String password = loginData.get("password");

        if (username == null || username.isBlank())
            throw new RuntimeException("Username is required");
        if (password == null || password.isBlank())
            throw new RuntimeException("Password is required");

        // Additional login logic would go here
        Users user = userRepository.findByUsername(username).orElseThrow(() -> new RuntimeException("User not found"));

        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new RuntimeException("Invalid username or password");
        }

        String accessToken = jwtUtil.generateToken(Map.of("id", user.getId(), "role", user.getRole()));
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getId());

        ResponseCookie cookie = ResponseCookie
                .from("refreshToken", refreshToken.getToken())
                .httpOnly(true)
                .secure(false)
                .sameSite("Lax")
                .path("/")
                .maxAge(Duration.ofDays(180))
                .build();
        return Map.of(
                "accessToken", accessToken,
                "cookie", cookie

        );
    }

    public Map<String, String> refresh(String refreshToken) {
        String newAccessToken = null;

        try {
            String userId = jwtUtil.extractIdString(refreshToken);
            Users user = userRepository.findById(userId)
                    .orElseThrow(() -> new RuntimeException("User not found"));
            newAccessToken = jwtUtil.generateToken(Map.of(
                    "id", user.getId().toString(),
                    "role", user.getRole()));
            // try{
            // RefreshToken storedToken = refreshTokenRepository.findByUserId(userId)
            // .orElseThrow(() -> new RuntimeException("Refresh token not found"));
            // storedToken.setRefresh(jwtUtil.generateRefreshToken(userId));
            // storedToken.setExpireAt(System.currentTimeMillis() + 1000L * 60 * 60 * 24 *
            // 30 * 6);
            // refreshTokenRepository.save(storedToken);
            // }catch(Exception e){
            // throw new RuntimeException("Refresh token not found: " + e.getMessage());
            // }

        } catch (Exception e) {
            throw new RuntimeException("Invalid refresh token: " + e.getMessage());
        }

        return Map.of("accessToken", newAccessToken);

        // throw new RuntimeException("User not found");
    }



}
