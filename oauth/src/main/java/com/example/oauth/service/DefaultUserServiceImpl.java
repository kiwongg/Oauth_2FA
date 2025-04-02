package com.example.oauth.service;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.oauth.dao.RoleRepository;
import com.example.oauth.dao.UserRepository;
import com.example.oauth.dto.UserRegisteredDTO;
import com.example.oauth.model.Role;
import com.example.oauth.model.User;
import org.springframework.dao.DataIntegrityViolationException;
import com.example.oauth.exception.GlobalExceptionHandler.CustomException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

@Service
public class DefaultUserServiceImpl implements DefaultUserService {
    @Autowired
    private UserRepository userRepo;

    @Autowired
    private RoleRepository roleRepo;


    private BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();


    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {

        User user = userRepo.findByEmail(email);
        if (user == null) {
            throw new UsernameNotFoundException("Invalid username or password.");
        }
        return new org.springframework.security.core.userdetails.User(user.getEmail(), user.getPassword(), mapRolesToAuthorities(user.getRole()));
    }

    private Collection<? extends GrantedAuthority> mapRolesToAuthorities(Set<Role> roles) {
        return roles.stream().map(role -> new SimpleGrantedAuthority(role.getRole())).collect(Collectors.toList());
    }

    @Override
    public User save(UserRegisteredDTO userRegisteredDTO) {
        if (userRepo.findByEmail(userRegisteredDTO.getEmail()) != null) {
            throw new CustomException("Email already registered");
        }

        User user = new User();
        user.setEmail(userRegisteredDTO.getEmail());
        user.setUsername(userRegisteredDTO.getName());
        user.setPassword(passwordEncoder.encode(userRegisteredDTO.getPassword()));

        // Handle roles
        Role role = roleRepo.findByRole("USER");
        if (role == null) {
            role = new Role();
            role.setRole("USER");
            role = roleRepo.save(role);
        }
        user.addRole(role);

        return userRepo.save(user);
    }


    public void authenticateUser(User user) {
        UserDetails userDetails = new org.springframework.security.core.userdetails.User(
                user.getEmail(), user.getPassword(), mapRolesToAuthorities(user.getRole())
        );

        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    public boolean verifyOtp(String email, String otp) {
        User user = userRepo.findByEmail(email);

        if (user != null && user.getOtp().equals(otp) && user.getOtpExpiration().isAfter(LocalDateTime.now())) {
            // OTP is valid, clear it and authenticate the user
            user.setOtp(null);
            user.setOtpExpiration(null);
            userRepo.save(user); // Save changes in the database

            authenticateUser(user); // Authenticate user after OTP verification
            return true;
        }

        return false;
    }

    public boolean checkPassword(User user, String rawPassword) {
        return passwordEncoder.matches(rawPassword, user.getPassword());
    }

}