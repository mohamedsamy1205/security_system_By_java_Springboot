package com.security.security.service;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.security.security.model.Users;
import com.security.security.repository.UserRepository;

@Service
public class UserService {
    @Autowired
    private UserRepository userRepository;
    
    public Optional<Users> me(String userId) {
        return userRepository.findById(userId);
    }
}
