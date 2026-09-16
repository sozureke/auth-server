package com.sozureke.auth_server.auth.dto;

import com.sozureke.auth_server.user.validation.ValidPassword;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record ChangePasswordRequest(
    @NotBlank @Email String email,
    @NotBlank String currentPassword,
    @NotBlank @ValidPassword String newPassword) {}
