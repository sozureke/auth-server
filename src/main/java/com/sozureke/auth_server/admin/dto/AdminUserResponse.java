package com.sozureke.auth_server.admin.dto;

import com.sozureke.auth_server.role.Role;
import com.sozureke.auth_server.user.User;
import java.time.LocalDateTime;
import java.util.Set;
import java.util.TreeSet;

public record AdminUserResponse(
    Long id,
    String email,
    boolean emailVerified,
    boolean enabled,
    boolean mfaEnabled,
    int failedLoginAttempts,
    LocalDateTime lockedUntil,
    Set<String> roles,
    LocalDateTime createdAt,
    LocalDateTime updatedAt) {

  public static AdminUserResponse from(User user) {
    Set<String> roles = new TreeSet<>();
    for (Role role : user.getRoles()) {
      roles.add(role.getName());
    }
    return new AdminUserResponse(
        user.getId(),
        user.getEmail(),
        user.isEmailVerified(),
        user.isEnabled(),
        user.isMfaEnabled(),
        user.getFailedLoginAttempts(),
        user.getLockedUntil(),
        roles,
        user.getCreatedAt(),
        user.getUpdatedAt());
  }
}
