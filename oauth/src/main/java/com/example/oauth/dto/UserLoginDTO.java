package com.example.oauth.dto;

import io.swagger.v3.oas.annotations.media.Schema;

public class UserLoginDTO {

    @Schema(description = "User's email address", example = "user@example.com", required = true)
    private String username;

    @Schema(description = "User's password", example = "Password@123", required = true)
    private String password;

    private int otp;


    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public int getOtp() {
        return otp;
    }

    public void setOtp(int otp) {
        this.otp = otp;
    }




}
