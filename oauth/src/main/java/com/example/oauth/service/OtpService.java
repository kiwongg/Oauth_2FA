package com.example.oauth.service;

import com.example.oauth.model.User;
import com.example.oauth.dao.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.LocalDateTime;

@Service
public class OtpService {

    @Autowired
    private UserRepository userRepository;

    private static final Logger logger = LoggerFactory.getLogger(OtpService.class);


    private static final int OTP_EXPIRATION_MINUTES = 5;
    private static final int OTP_LENGTH = 6;

    private final SecureRandom random = new SecureRandom();

    public String generateOtp(User user) {
        String otp = String.format("%06d", random.nextInt(999999));
        user.setOtp(otp);
        user.setOtpExpiration(LocalDateTime.now().plusMinutes(OTP_EXPIRATION_MINUTES));
        userRepository.save(user);
        return otp;
    }


    public void clearOtp(User user) {
        user.setOtp(null);
        user.setOtpExpiration(null);
        userRepository.save(user);
    }
    public boolean verifyOtp(User user, String otp) {
        boolean isValid = user.getOtp() != null &&
                user.getOtp().equals(otp) &&
                user.getOtpExpiration().isAfter(LocalDateTime.now());

        logger.debug("OTP verification for user {}: {}", user.getEmail(),
                isValid ? "SUCCESS" : "FAILED");
        logger.debug("Stored OTP: {}, Provided OTP: {}, Expiration: {}",
                user.getOtp(), otp, user.getOtpExpiration());

        return isValid;
    }

}