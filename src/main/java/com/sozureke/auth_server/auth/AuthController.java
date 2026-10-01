package com.sozureke.auth_server.auth;

import com.sozureke.auth_server.auth.dto.ChangeEmailRequest;
import com.sozureke.auth_server.auth.dto.ChangePasswordRequest;
import com.sozureke.auth_server.auth.dto.LoginRequest;
import com.sozureke.auth_server.auth.dto.PasswordResetConfirmRequest;
import com.sozureke.auth_server.auth.dto.PasswordResetRequest;
import com.sozureke.auth_server.user.dto.UserResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@Tag(name = "Account", description = "Login check, password and email management")
public class AuthController {
  private final AuthService authService;

  public AuthController(AuthService authService) {
    this.authService = authService;
  }

  @PostMapping("/login")
  @SecurityRequirements
  @Operation(
      summary = "Check credentials",
      description =
          "Verifies email and password and the account state. Issues no token or session: tokens"
              + " come from the OAuth 2.0 flow. Rate limited per IP and email; 5 wrong passwords"
              + " lock the account for 15 minutes.")
  @ApiResponse(responseCode = "200", description = "Credentials valid")
  @ApiResponse(responseCode = "401", description = "Wrong email or password")
  @ApiResponse(responseCode = "403", description = "Email not verified or account disabled")
  @ApiResponse(responseCode = "423", description = "Account locked")
  @ApiResponse(responseCode = "429", description = "Rate limit exceeded")
  public ResponseEntity<UserResponse> login(@Valid @RequestBody LoginRequest request) {
    UserResponse response = authService.login(request.email(), request.password());
    return ResponseEntity.ok(response);
  }

  @PutMapping("/password")
  @SecurityRequirements
  @Operation(
      summary = "Change password",
      description =
          "Requires the current password. Wrong attempts count towards the account lockout.")
  @ApiResponse(responseCode = "200", description = "Password changed")
  @ApiResponse(responseCode = "401", description = "Wrong email or current password")
  @ApiResponse(responseCode = "423", description = "Account locked")
  public ResponseEntity<UserResponse> changePassword(
      @Valid @RequestBody ChangePasswordRequest request) {
    UserResponse response =
        authService.changePassword(
            request.email(), request.currentPassword(), request.newPassword());
    return ResponseEntity.ok(response);
  }

  @PostMapping("/password-reset-request")
  @SecurityRequirements
  @Operation(
      summary = "Request a password reset link",
      description =
          "Always returns 200, whether or not the email exists, so it cannot be used to discover"
              + " accounts. The link is valid for one hour.")
  public ResponseEntity<Void> requestPasswordReset(
      @Valid @RequestBody PasswordResetRequest request) {
    authService.requestPasswordReset(request.email());
    return ResponseEntity.ok().build();
  }

  @PostMapping("/password-reset")
  @SecurityRequirements
  @Operation(summary = "Set a new password with a reset token")
  @ApiResponse(responseCode = "200", description = "Password reset")
  @ApiResponse(responseCode = "400", description = "Token invalid or expired, or weak password")
  public ResponseEntity<Void> resetPassword(
      @Valid @RequestBody PasswordResetConfirmRequest request) {
    authService.resetPassword(request.token(), request.newPassword());
    return ResponseEntity.ok().build();
  }

  @GetMapping("/me")
  @Operation(summary = "Current user")
  public ResponseEntity<UserResponse> me(
      @Parameter(hidden = true) @AuthenticationPrincipal AuthUserDetails principal) {
    return ResponseEntity.ok(UserResponse.from(principal.getUser()));
  }

  @PutMapping("/me")
  @Operation(
      summary = "Change email",
      description = "Requires the current password. The new address has to be verified again.")
  public ResponseEntity<UserResponse> updateEmail(
      @Parameter(hidden = true) @AuthenticationPrincipal AuthUserDetails principal,
      @Valid @RequestBody ChangeEmailRequest request) {
    UserResponse response =
        authService.changeEmail(principal.getUser(), request.currentPassword(), request.newEmail());
    return ResponseEntity.ok(response);
  }
}
