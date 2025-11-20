package com.security.security.config;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.security.security.model.Users;
import com.security.security.repository.UserRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
@Service
@RequiredArgsConstructor
@Slf4j
public class CustomUserService implements UserDetailsService {
    @Autowired
    private UserRepository userRepositry;


    private final static String ROLE_PREFIX = "ROLE_";

    // The explicit constructor is removed as @RequiredArgsConstructor generates it automatically.

    @Override
    public UserDetails loadUserByUsername(String id) throws UsernameNotFoundException {
        Optional<Users> user = userRepositry.findById(id);
        user.orElseThrow(() -> new UsernameNotFoundException("User not found"));
        String username = user.get().getUsername();
        log.info("User : {}", user.get());
        log.info("UserName : {}", username);
        String password = user.get().getPassword();
        log.info("Password : {}", password);
        String role = user.get().getRole();
        log.info("Role : {}", role);
        role= ROLE_PREFIX+role;
        List<GrantedAuthority> roles = new ArrayList<>();
        roles.add(new SimpleGrantedAuthority(role));

        return new CustomUserDetails(username, password, roles);
    }
}

