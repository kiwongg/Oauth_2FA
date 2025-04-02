package com.example.oauth.contolller;



import com.example.oauth.service.DefaultUserService;
import com.example.oauth.dao.UserRepository;
import com.example.oauth.service.EmailService;
import com.example.oauth.service.OtpService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import com.example.oauth.dao.UserRepository;
import com.example.oauth.dto.UserLoginDTO;
import com.example.oauth.model.User;
import com.example.oauth.service.DefaultUserService;



@Controller
@Tag(name = "Authentication", description = "Login API")
@RequestMapping("/login")
public class LoginController {

    @Autowired
    private DefaultUserService userService;

    @Autowired
    private UserRepository userRepo;

    @Autowired
    private OtpService otpService;

    @Autowired
    private EmailService emailService;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @ModelAttribute("user")
    public UserLoginDTO userLoginDTO() {
        return new UserLoginDTO();
    }

    @GetMapping
    public String login(Model model,
                        @RequestParam(value = "error", required = false) String error,
                        @RequestParam(value = "logout", required = false) String logout,
                        @RequestParam(value = "oauth2Error", required = false) String oauth2Error) {

        if (error != null) {
            model.addAttribute("error", "Invalid email or password");
        }
        if (logout != null) {
            model.addAttribute("message", "You have been logged out successfully");
        }
        if (oauth2Error != null) {
            model.addAttribute("error", "OAuth2 login failed. Please try again.");
        }

        return "login";
    }


}