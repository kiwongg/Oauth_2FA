package com.example.oauth.config;


import java.io.IOException;
import java.util.UUID;
import java.util.Set;
import java.util.HashSet;
import com.example.oauth.service.DefaultUserService;
import com.example.oauth.service.EmailService;
import com.example.oauth.service.OtpService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import com.example.oauth.dao.UserRepository;
import com.example.oauth.dao.RoleRepository;
import com.example.oauth.dto.UserRegisteredDTO;
import com.example.oauth.model.User;
import com.example.oauth.model.Role;
import org.slf4j.Logger;

// Remove @Component if using Solution 1
// @Component

public class CustomSuccessHandler implements AuthenticationSuccessHandler {

    @Autowired
    private UserRepository userRepo;

    @Autowired
    private OtpService otpService;

    @Autowired
    private EmailService emailService;

    @Autowired
    private RoleRepository roleRepo;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    private static final Logger logger = LoggerFactory.getLogger(CustomSuccessHandler.class);

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {

        HttpSession session = request.getSession();
        String email = authentication.getName();

        // Handle both OAuth and regular login
        if (authentication.getPrincipal() instanceof DefaultOAuth2User) {
            DefaultOAuth2User oauthUser = (DefaultOAuth2User) authentication.getPrincipal();
            email = oauthUser.getAttribute("email");

            // GitHub specific handling
            if (email == null) {
                email = oauthUser.getAttribute("login") + "@github.com";
            }

            // Create user if not exists (OAuth only)
            if (userRepo.findByEmail(email) == null) {
                createOAuthUser(oauthUser, email);
            }
        }

        User user = userRepo.findByEmail(email);
        if (user != null) {
            String otp = otpService.generateOtp(user);
            emailService.sendOtpEmail(user.getEmail(), otp);
            session.setAttribute("otpUserEmail", email);
            response.sendRedirect("/verify-otp");
        } else {
            response.sendRedirect("/login?error=user_not_found");
        }
    }

    private void createOAuthUser(DefaultOAuth2User oauthUser, String email) {
        User user = new User();
        user.setEmail(email);
        user.setUsername(oauthUser.getAttribute("name") != null ?
                oauthUser.getAttribute("name") : oauthUser.getAttribute("login"));
        user.setPassword(passwordEncoder.encode(UUID.randomUUID().toString()));

        Role role = roleRepo.findByRole("USER");
        if (role == null) {
            role = new Role();
            role.setRole("USER");
            role = roleRepo.save(role);
        }
        user.addRole(role);
        userRepo.save(user);

        logger.info("Created new user for OAuth login: {}", email);
    }
}