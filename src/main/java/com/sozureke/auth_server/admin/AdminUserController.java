package com.sozureke.auth_server.admin;

import com.sozureke.auth_server.admin.dto.AdminUserResponse;
import com.sozureke.auth_server.auth.AuthUserDetails;
import java.util.Map;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin/users")
public class AdminUserController {

  private final AdminUserService adminUserService;

  public AdminUserController(AdminUserService adminUserService) {
    this.adminUserService = adminUserService;
  }

  @GetMapping
  @PreAuthorize("hasAuthority('USER_READ')")
  public Page<AdminUserResponse> list(
      @RequestParam(required = false) String query,
      @PageableDefault(size = 20, sort = "id", direction = Sort.Direction.ASC) Pageable pageable) {
    return adminUserService.search(query, pageable).map(AdminUserResponse::from);
  }

  @GetMapping("/{id}")
  @PreAuthorize("hasAuthority('USER_READ')")
  public AdminUserResponse get(@PathVariable Long id) {
    return AdminUserResponse.from(adminUserService.get(id));
  }

  @PutMapping("/{id}/disable")
  @PreAuthorize("hasAuthority('USER_WRITE')")
  public AdminUserResponse disable(
      @AuthenticationPrincipal AuthUserDetails principal, @PathVariable Long id) {
    return AdminUserResponse.from(adminUserService.disable(principal.getUser().getId(), id));
  }

  @DeleteMapping("/{id}")
  @PreAuthorize("hasAuthority('USER_WRITE')")
  public ResponseEntity<Void> delete(
      @AuthenticationPrincipal AuthUserDetails principal, @PathVariable Long id) {
    adminUserService.delete(principal.getUser().getId(), id);
    return ResponseEntity.noContent().build();
  }

  @PostMapping("/{id}/force-logout")
  @PreAuthorize("hasAuthority('USER_WRITE')")
  public Map<String, Integer> forceLogout(
      @AuthenticationPrincipal AuthUserDetails principal, @PathVariable Long id) {
    return Map.of("sessionsRevoked", adminUserService.forceLogout(principal.getUser().getId(), id));
  }
}
