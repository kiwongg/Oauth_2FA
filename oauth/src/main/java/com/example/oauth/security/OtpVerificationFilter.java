package com.example.oauth.security;

import com.example.oauth.model.User;
import com.example.oauth.dao.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class OtpVerificationFilter extends OncePerRequestFilter {

    @Autowired
    private UserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String path = request.getRequestURI();

        // Skip OTP check for these paths
        if (shouldSkipPath(path)) {
            filterChain.doFilter(request, response);
            return;
        }

        HttpSession session = request.getSession(false);
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        // For all authenticated requests to protected paths
        if (auth != null && auth.isAuthenticated() && isProtectedPath(path)) {

            // Strict check - must have otpVerified flag
            if (session == null || session.getAttribute("otpVerified") == null) {
                response.sendRedirect("/verify-otp");
                return;
            }
        }

        filterChain.doFilter(request, response);
    }

    private boolean shouldSkipPath(String path) {
        return path.startsWith("/login") ||
                path.startsWith("/verify-otp") ||
                path.startsWith("/static") ||
                path.startsWith("/error") ||
                path.equals("/");
    }

    private boolean isProtectedPath(String path) {
        return path.startsWith("/dashboard") ||
                path.startsWith("/api/pincode");
    }
}
