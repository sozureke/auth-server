package com.sozureke.auth_server.user.dto;

import java.time.LocalDateTime;
import com.sozureke.auth_server.user.User;

public record UserResponse(Long id, String email, boolean emailVerified, LocalDateTime createdAt) {

    public static UserResponse from(User user) {
        return new UserResponse(user.getId(), user.getEmail(), user.isEmailVerified(), user.getCreatedAt());
    }
}