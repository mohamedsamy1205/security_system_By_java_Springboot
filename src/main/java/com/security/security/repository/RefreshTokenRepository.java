package com.security.security.repository;

import org.springframework.data.mongodb.repository.MongoRepository;

import com.security.security.model.RefreshToken;
// import com.security.security.model.Users;

public interface RefreshTokenRepository extends MongoRepository<RefreshToken, String> {
    RefreshToken findByToken(String token);

    void deleteByToken(String token);

    void deleteByUserId(String userId);
        

}
