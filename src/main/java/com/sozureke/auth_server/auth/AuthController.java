package com.sozureke.auth_server.auth;

import com.sozureke.auth_server.auth.dto.ChangePasswordRequest;
import com.sozureke.auth_server.auth.dto.LoginRequest;
import com.sozureke.auth_server.auth.dto.PasswordResetConfirmRequest;
import com.sozureke.auth_server.auth.dto.PasswordResetRequest;
import com.sozureke.auth_server.user.dto.UserResponse;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {
  private final AuthService authService;

  public AuthController(AuthService authService) {
    this.authService = authService;
  }

  @PostMapping("/login")
  public ResponseEntity<UserResponse> login(@Valid @RequestBody LoginRequest request) {
    UserResponse response = authService.login(request.email(), request.password());
    return ResponseEntity.ok(response);
  }

  @PutMapping("/password")
  public ResponseEntity<UserResponse> changePassword(
      @Valid @RequestBody ChangePasswordRequest request) {
    UserResponse response =
        authService.changePassword(
            request.email(), request.currentPassword(), request.newPassword());
    return ResponseEntity.ok(response);
  }

  @PostMapping("/password-reset-request")
  public ResponseEntity<Void> requestPasswordReset(
      @Valid @RequestBody PasswordResetRequest request) {
    authService.requestPasswordReset(request.email());
    return ResponseEntity.ok().build();
  }

  @PostMapping("/password-reset")
  public ResponseEntity<Void> resetPassword(
      @Valid @RequestBody PasswordResetConfirmRequest request) {
    authService.resetPassword(request.token(), request.newPassword());
    return ResponseEntity.ok().build();
  }
}
