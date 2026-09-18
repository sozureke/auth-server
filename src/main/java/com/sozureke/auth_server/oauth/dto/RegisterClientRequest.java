package com.sozureke.auth_server.oauth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import java.util.Set;

public record RegisterClientRequest(
    @NotBlank String clientId,
    @NotBlank String clientName,
    @NotEmpty Set<String> redirectUris,
    @NotEmpty Set<String> scopes) {}
