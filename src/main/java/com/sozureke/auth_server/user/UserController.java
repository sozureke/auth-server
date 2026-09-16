package com.sozureke.auth_server.user;

import com.sozureke.auth_server.user.dto.RegisterRequest;
import com.sozureke.auth_server.user.dto.UserResponse;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class UserController {
  private final UserService userService;

  public UserController(UserService userService) {
    this.userService = userService;
  }

  @PostMapping("/register")
  public ResponseEntity<UserResponse> register(@Valid @RequestBody RegisterRequest request) {
    User user = userService.register(request.getEmail(), request.getPassword());
    return ResponseEntity.status(HttpStatus.CREATED).body(UserResponse.from(user));
  }

  @GetMapping("/verify")
  public ResponseEntity<UserResponse> verifyEmail(@RequestParam("token") String token) {
    User user = userService.verifyEmail(token);
    return ResponseEntity.ok(UserResponse.from(user));
  }
}
