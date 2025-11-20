package com.security.security.service;

import java.util.List;
import java.util.Map;

// import org.springframework.security.core.Authentication;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
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

    public ResponseEntity<String> registerUser(Map<String, String> userData) {
        String username = userData.get("username");
        String email = userData.get("email");
        String password = userData.get("password");
        String role = userData.get("role");

        if (username == null || username.isBlank())
            return ResponseEntity.badRequest().body("Username is required");
        if (email == null || email.isBlank() || !email.matches("^[A-Za-z0-9+_.-]+@(.+)$"))
            return ResponseEntity.badRequest().body("Invalid email format");
        if (password == null || password.isBlank())
            return ResponseEntity.badRequest().body("Password is required");
        if (!password.matches("^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=!]).{8,}$"))
            return ResponseEntity.badRequest().body("Weak password");
        if (userRepository.existsByEmail(email))
            return ResponseEntity.badRequest().body("Email already registered");
        if (userRepository.existsByUsername(username))
            return ResponseEntity.badRequest().body("Username already taken");
        if (!List.of("USER", "ADMIN").contains(role))
            return ResponseEntity.badRequest().body("Invalid role");

        userRepository.save(Users.builder()
                .username(username)
                .email(email)
                .password(passwordEncoder.encode(password))
                .role(role)
                .isActivated(false)
                .build());

        return ResponseEntity.ok("User registered successfully");
    }

    public ResponseEntity<?> loginUser (Map<String, String> loginData) {
        String username = loginData.get("username");
        String password = loginData.get("password");

        if (username == null || username.isBlank())
            return ResponseEntity.badRequest().body("Username is required");
        if (password == null || password.isBlank())
            return ResponseEntity.badRequest().body("Password is required");

        // Additional login logic would go here
        Users user = userRepository.findByUsername(username).orElseThrow(() -> 
            new RuntimeException("User not found"));

        if (!passwordEncoder.matches(password, user.getPassword())) {
            return ResponseEntity.badRequest().body("Invalid username or password");
        }

        String accessToken = jwtUtil.generateToken(Map.of("id", user.getId(), "role", user.getRole()));
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getId());
        return ResponseEntity.ok(Map.of(
            "accessToken",accessToken,
            "refreshToken",refreshToken.getToken()
        ));
    }



}
