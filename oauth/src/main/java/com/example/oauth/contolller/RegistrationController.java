package com.example.oauth.contolller;

import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.ui.Model;
import com.example.oauth.exception.GlobalExceptionHandler;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import jakarta.validation.Valid;
import org.springframework.validation.BindingResult;
import com.example.oauth.dto.UserRegisteredDTO;
import com.example.oauth.service.DefaultUserService;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.Operation;

@Controller
@RequestMapping("/registration")
@Tag(name = "Authentication", description = "Registration API")
public class RegistrationController {

    private final DefaultUserService userService;

    public RegistrationController(DefaultUserService userService) {
        this.userService = userService;
    }

    @ModelAttribute("user")
    public UserRegisteredDTO userRegistrationDto() {
        return new UserRegisteredDTO();
    }

    @Operation(summary = "Registration form", description = "Displaying the registration form")
    @ApiResponse(responseCode = "200", description = "Registration form displayed")
    @GetMapping
    public String showRegisterForm() {
        return "register";
    }

    @Operation(summary = "User Registration", description = "Handles user registration submission")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "302", description = "Redirect to login on success"),
            @ApiResponse(responseCode = "400", description = "Validation errors")
    })
    @PostMapping
    public String registerUserAccount(@ModelAttribute("user") @Valid UserRegisteredDTO registrationDto,
                                      BindingResult result, Model model) {
        if (result.hasErrors()) {
            // Add detailed error messages
            result.getFieldErrors().forEach(error -> {
                model.addAttribute(error.getField() + "Error", error.getDefaultMessage());
            });
            return "register";
        }

        try {
            userService.save(registrationDto);
        } catch (GlobalExceptionHandler.CustomException e) {
            model.addAttribute("error", e.getMessage());
            return "register";
        }

        return "redirect:/login?success";
    }
}