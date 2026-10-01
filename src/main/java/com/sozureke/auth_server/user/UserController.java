package com.sozureke.auth_server.user;

import com.sozureke.auth_server.user.dto.RegisterRequest;
import com.sozureke.auth_server.user.dto.UserResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@Tag(name = "Registration", description = "Sign-up and email verification")
public class UserController {
  private final UserService userService;

  public UserController(UserService userService) {
    this.userService = userService;
  }

  @PostMapping("/register")
  @SecurityRequirements
  @Operation(
      summary = "Register an account",
      description =
          "Creates an unverified account and sends a verification link. Rate limited to 3 per"
              + " hour per IP.")
  @ApiResponse(responseCode = "201", description = "Account created, email not yet verified")
  @ApiResponse(responseCode = "400", description = "Invalid email or weak password")
  @ApiResponse(responseCode = "409", description = "Email already registered")
  @ApiResponse(responseCode = "429", description = "Rate limit exceeded")
  public ResponseEntity<UserResponse> register(@Valid @RequestBody RegisterRequest request) {
    User user = userService.register(request.getEmail(), request.getPassword());
    return ResponseEntity.status(HttpStatus.CREATED).body(UserResponse.from(user));
  }

  @GetMapping("/verify")
  @SecurityRequirements
  @Operation(summary = "Verify email with the token from the verification link")
  @ApiResponse(responseCode = "200", description = "Email verified")
  @ApiResponse(responseCode = "404", description = "Unknown token")
  public ResponseEntity<UserResponse> verifyEmail(@RequestParam("token") String token) {
    User user = userService.verifyEmail(token);
    return ResponseEntity.ok(UserResponse.from(user));
  }
}
