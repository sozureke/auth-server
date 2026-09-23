package com.sozureke.auth_server.mfa.dto;

import jakarta.validation.constraints.NotBlank;

public record MfaDisableRequest(@NotBlank String password) {}
