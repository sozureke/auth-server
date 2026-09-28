package com.sozureke.auth_server.admin.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import java.util.Set;

public record UpdateClientRequest(
    @NotBlank String clientName,
    @NotEmpty Set<@NotBlank String> redirectUris,
    @NotEmpty Set<@NotBlank String> scopes) {}
