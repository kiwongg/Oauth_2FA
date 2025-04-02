package com.example.oauth.contolller;


import com.example.oauth.model.User;
import com.example.oauth.dao.UserRepository;
import com.example.oauth.service.EmailService;
import com.example.oauth.service.OtpService;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@Controller
public class OtpController {

    @Autowired
    private OtpService otpService;

    @Autowired
    private EmailService emailService;

    @Autowired
    private UserRepository userRepository;

    @GetMapping("/verify-otp")
    public String showOtpPage(Model model, HttpSession session) {
        String email = (String) session.getAttribute("otpUserEmail");
        if (email == null) {
            return "redirect:/login";
        }
        model.addAttribute("title", "OTP Verification");
        return "otp-verification";
    }

    @PostMapping("/verify-otp")
    public String verifyOtp(@RequestParam("otp") String otp,
                            HttpSession session,
                            Model model) {
        String email = (String) session.getAttribute("otpUserEmail");
        if (email == null) {
            return "redirect:/login";
        }

        User user = userRepository.findByEmail(email);
        if (user == null) {
            model.addAttribute("error", "User not found.");
            return "otp-verification";
        }

        if (otpService.verifyOtp(user, otp)) {
            otpService.clearOtp(user);
            session.removeAttribute("otpUserEmail");
            session.setAttribute("otpVerified", System.currentTimeMillis());
            return "redirect:/dashboard";
        } else {
            model.addAttribute("error", "Invalid or expired OTP.");
            return "otp-verification";
        }
    }

    @GetMapping("/resend-otp")
    public String resendOtp(HttpSession session, Model model) {
        String email = (String) session.getAttribute("otpUserEmail");
        if (email == null) {
            return "redirect:/login";
        }

        User user = userRepository.findByEmail(email);
        if (user == null) {
            model.addAttribute("error", "User not found.");
            return "otp-verification";
        }

        try {
            String otp = otpService.generateOtp(user);
            emailService.sendOtpEmail(user.getEmail(), otp);
            model.addAttribute("message", "New OTP has been sent to your email.");
        } catch (Exception e) {
            model.addAttribute("error", "Failed to resend OTP. Please try again.");
        }

        return "otp-verification";
    }
}
