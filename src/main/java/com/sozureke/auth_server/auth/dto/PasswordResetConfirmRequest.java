package com.sozureke.auth_server.auth.dto;

import com.sozureke.auth_server.user.validation.ValidPassword;
import jakarta.validation.constraints.NotBlank;

public record PasswordResetConfirmRequest(
    @NotBlank String token, @NotBlank @ValidPassword String newPassword) {}
