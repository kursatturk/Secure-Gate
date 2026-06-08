package com.securegate.model;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class RegisterRequest {
    @NotBlank
    private String username;
    private String email;
    @NotBlank
    private String password;
    private String role = "ROLE_USER";
}
