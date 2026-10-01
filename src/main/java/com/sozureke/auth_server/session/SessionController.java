package com.sozureke.auth_server.session;

import com.sozureke.auth_server.auth.AuthUserDetails;
import com.sozureke.auth_server.config.OpenApiConfig;
import com.sozureke.auth_server.session.dto.SessionSummary;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth/sessions")
@Tag(
    name = "Sessions",
    description =
        "Browser sessions of the signed-in user. Authenticated by the SESSION cookie from the"
            + " login form; state-changing calls need a CSRF token.")
@SecurityRequirement(name = OpenApiConfig.SESSION_COOKIE)
public class SessionController {
  private final SessionManagementService sessionManagementService;

  public SessionController(SessionManagementService sessionManagementService) {
    this.sessionManagementService = sessionManagementService;
  }

  @GetMapping
  @Operation(
      summary = "List my sessions",
      description = "Session ids are returned as SHA-256 hashes, never as the id itself.")
  public List<SessionSummary> list(
      @Parameter(hidden = true) @AuthenticationPrincipal AuthUserDetails principal,
      HttpServletRequest request) {
    return sessionManagementService.listSessions(
        principal.getUser().getEmail(), request.getSession().getId());
  }

  @DeleteMapping("/{hash}")
  @Operation(summary = "Revoke one of my sessions")
  @ApiResponse(responseCode = "204", description = "Session revoked")
  @ApiResponse(responseCode = "404", description = "No such session for this user")
  public ResponseEntity<Void> revoke(
      @Parameter(hidden = true) @AuthenticationPrincipal AuthUserDetails principal,
      @Parameter(description = "SHA-256 hash from the session list") @PathVariable String hash) {
    sessionManagementService.revoke(principal.getUser().getEmail(), hash);
    return ResponseEntity.noContent().build();
  }

  @DeleteMapping
  @Operation(summary = "Revoke all my other sessions", description = "Keeps the current one.")
  @ApiResponse(responseCode = "204", description = "Other sessions revoked")
  public ResponseEntity<Void> revokeAllExceptCurrent(
      @Parameter(hidden = true) @AuthenticationPrincipal AuthUserDetails principal,
      HttpServletRequest request) {
    sessionManagementService.revokeAllExceptCurrent(
        principal.getUser().getEmail(), request.getSession().getId());
    return ResponseEntity.noContent().build();
  }
}
