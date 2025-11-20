package com.security.security.jwts;

// import java.time.Instant;
import java.util.Map;
// import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.boot.autoconfigure.data.redis.RedisProperties.Lettuce.Cluster.Refresh;
// import org.springframework.boot.autoconfigure.security.SecurityProperties.User;
import org.springframework.stereotype.Service;

import com.security.security.model.RefreshToken;
import com.security.security.model.Users;
import com.security.security.repository.RefreshTokenRepository;
import com.security.security.repository.UserRepository;

// import io.jsonwebtoken.Jwts;

@Service
public class RefreshTokenService {
    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private JWTUtil jwtUtil;

    private final long REFRESH_TOKEN_EXPIRATION = 1000L * 60 * 60 * 24 * 30 * 6; // 6 أشهر

    public RefreshToken createRefreshToken(String userId) {
        Users user = userRepository.findById(userId).orElseThrow(() -> new IllegalArgumentException("User not found"));
        String token = jwtUtil.generateRefreshToken(Map.of("id", user.getId(), "role", user.getRole()));
        RefreshToken refreshToken = new RefreshToken();
        // حفظ رمز التحديث في قاعدة البيانات
        refreshToken.setToken(token);
        refreshToken.setUserId(userId);
        refreshToken.setExpiryDate(System.currentTimeMillis() + REFRESH_TOKEN_EXPIRATION);
        refreshTokenRepository.deleteByUserId(user.getId());
        refreshTokenRepository.save(refreshToken);
        return refreshToken;
    }
}
