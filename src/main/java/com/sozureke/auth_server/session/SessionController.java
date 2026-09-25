package com.sozureke.auth_server.session;

import com.sozureke.auth_server.auth.AuthUserDetails;
import com.sozureke.auth_server.session.dto.SessionSummary;
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
public class SessionController {
  private final SessionManagementService sessionManagementService;

  public SessionController(SessionManagementService sessionManagementService) {
    this.sessionManagementService = sessionManagementService;
  }

  @GetMapping
  public List<SessionSummary> list(
      @AuthenticationPrincipal AuthUserDetails principal, HttpServletRequest request) {
    return sessionManagementService.listSessions(
        principal.getUser().getEmail(), request.getSession().getId());
  }

  @DeleteMapping("/{hash}")
  public ResponseEntity<Void> revoke(
      @AuthenticationPrincipal AuthUserDetails principal, @PathVariable String hash) {
    sessionManagementService.revoke(principal.getUser().getEmail(), hash);
    return ResponseEntity.noContent().build();
  }

  @DeleteMapping
  public ResponseEntity<Void> revokeAllExceptCurrent(
      @AuthenticationPrincipal AuthUserDetails principal, HttpServletRequest request) {
    sessionManagementService.revokeAllExceptCurrent(
        principal.getUser().getEmail(), request.getSession().getId());
    return ResponseEntity.noContent().build();
  }
}
