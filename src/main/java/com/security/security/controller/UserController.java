package com.security.security.controller;

// import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
// import org.springframework.boot.autoconfigure.security.SecurityProperties.User;
import org.springframework.web.bind.annotation.RestController;

import com.security.security.jwts.JWTUtil;
import com.security.security.model.Users;
import com.security.security.service.UserService;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
// import org.springframework.web.bind.annotation.RequestParam;


@RestController
@RequestMapping("/api/v1/user")
public class UserController {
    @Autowired
    private UserService userService;

    @Autowired
    private JWTUtil jwtUtil;


    @GetMapping("/me")
    public ResponseEntity<?> me(HttpServletRequest request) {
        String auth = request.getHeader("Authorization"); // استخرج معرف المستخدم من سياق الأمان
        String token = auth.substring(7); // افترض أن المعرف يبدأ بـ "Bearer "
        String userId = jwtUtil.extractIdString(token);
        Users user = userService.me(userId).orElseThrow(() -> new RuntimeException("User not found"));
        return ResponseEntity.ok(user);
    }
}
