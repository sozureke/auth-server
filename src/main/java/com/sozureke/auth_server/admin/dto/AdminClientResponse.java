package com.sozureke.auth_server.admin.dto;

import com.sozureke.auth_server.oauth.OAuthClient;
import java.time.LocalDateTime;
import java.util.Set;
import java.util.TreeSet;

public record AdminClientResponse(
    String clientId,
    String clientName,
    Set<String> redirectUris,
    Set<String> scopes,
    Set<String> grantTypes,
    boolean requireProofKey,
    LocalDateTime createdAt,
    LocalDateTime updatedAt) {

  public static AdminClientResponse from(OAuthClient client) {
    return new AdminClientResponse(
        client.getClientId(),
        client.getClientName(),
        new TreeSet<>(client.getRedirectUris()),
        new TreeSet<>(client.getScopes()),
        new TreeSet<>(client.getAuthorizationGrantTypes()),
        client.isRequireProofKey(),
        client.getCreatedAt(),
        client.getUpdatedAt());
  }
}
