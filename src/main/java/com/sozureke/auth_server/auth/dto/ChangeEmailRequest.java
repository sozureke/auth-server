package com.sozureke.auth_server.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record ChangeEmailRequest(
    @NotBlank String currentPassword, @NotBlank @Email String newEmail) {}
