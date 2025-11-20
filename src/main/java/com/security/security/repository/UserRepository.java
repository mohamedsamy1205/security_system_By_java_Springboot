package com.security.security.repository;

import java.util.Optional;

// import org.springframework.boot.autoconfigure.security.SecurityProperties.User;
import org.springframework.data.mongodb.repository.MongoRepository;

import com.security.security.model.Users;

public interface UserRepository extends MongoRepository<Users, String> {
    Optional<Users> findByUsername(String username);
    
    boolean existsByEmail(String email);

    boolean existsByUsername(String username);
}
