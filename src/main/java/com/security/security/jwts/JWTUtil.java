package com.security.security.jwts;

// import javax.crypto.SecretKey;

// import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import com.mongodb.Function;
import com.security.security.model.Users;

import java.security.Key;
import java.sql.Date;
import java.util.Map;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
@Component
public class JWTUtil {
    private final String SECRET_KEY = "12345678901234567890123456789012";
    private Key getSignInKey() {
        return Keys.hmacShaKeyFor(SECRET_KEY.getBytes());
    }

    private final long REFRESH_TOKEN_EXPIRATION = 1000L * 60 * 60 * 24 * 30 * 6; // 6 Months
    private long expiration = 1000 * 60 * 15; // 15 minutes

    public String generateToken(Map<String, String> userData) {
        String id = userData.get("id");
        String role = userData.get("role");
        if (id == null || role == null || role.isBlank() || id.isBlank())
            throw new IllegalArgumentException("User data must contain 'id' and 'role'");
        return Jwts.builder()
                .setId(id)
                .claim("role", role)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(SignatureAlgorithm.HS256, getSignInKey())
                .compact();
    }

    public String generateRefreshToken(Map<String, String> userData) {
        String id = userData.get("id");
        String role = userData.get("role");
        if (id == null || role == null || role.isBlank() || id.isBlank())
            throw new IllegalArgumentException("User data must contain 'id' and 'role'");
        return Jwts.builder()
                .setId(id)
                .claim("role", role)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + REFRESH_TOKEN_EXPIRATION))
                .signWith(SignatureAlgorithm.HS256, getSignInKey())
                .compact();
    }

    public String extractIdString(String token) {
        return extractClaim(token, Claims::getId);
    }
    public String extractUserRole(String token) {
        return extractClaim(token, claims -> claims.get("role", String.class));
    }
    private <T> T extractClaim(String token, Function<Claims, T> resolver) {
        final Claims claims = Jwts.parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
        return resolver.apply(claims);
    }
    public boolean isTokenValid(String token, Users user) {
        String id = extractIdString(token);
        return (id.equals(user.getId()) && !isTokenExpired(token));
    }
    private boolean isTokenExpired(String token) {
        return Jwts.parser()
                .setSigningKey(getSignInKey())
                .parseClaimsJws(token)
                .getBody()
                .getExpiration()
                .before(new Date(System.currentTimeMillis()));
    }
}
