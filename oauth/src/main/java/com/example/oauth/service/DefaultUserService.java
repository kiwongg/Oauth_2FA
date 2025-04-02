package com.example.oauth.service;

import com.example.oauth.dto.UserRegisteredDTO;
import com.example.oauth.model.User;
import org.springframework.security.core.userdetails.UserDetailsService;

public interface DefaultUserService extends UserDetailsService {
    User save(UserRegisteredDTO userRegisteredDTO);
//	User save(User user);
//	User findByEmail(String email);
}
