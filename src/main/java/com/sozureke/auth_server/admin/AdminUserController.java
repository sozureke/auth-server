package com.sozureke.auth_server.admin;

import com.sozureke.auth_server.admin.dto.AdminUserResponse;
import com.sozureke.auth_server.auth.AuthUserDetails;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.Map;
import org.springdoc.core.annotations.ParameterObject;
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
@Tag(
    name = "Admin: users",
    description = "Reads need USER_READ, changes need USER_WRITE. Every change is audited.")
public class AdminUserController {

  private final AdminUserService adminUserService;

  public AdminUserController(AdminUserService adminUserService) {
    this.adminUserService = adminUserService;
  }

  @GetMapping
  @PreAuthorize("hasAuthority('USER_READ')")
  @Operation(
      summary = "List and search users",
      description =
          "query matches a fragment of the email, case-insensitive; % and _ are literal. sort is"
              + " limited to id, email, createdAt, enabled.")
  @ApiResponse(responseCode = "200", description = "Page of users")
  @ApiResponse(responseCode = "400", description = "Unsupported sort property")
  public Page<AdminUserResponse> list(
      @RequestParam(required = false) String query,
      @ParameterObject @PageableDefault(size = 20, sort = "id", direction = Sort.Direction.ASC)
          Pageable pageable) {
    return adminUserService.search(query, pageable).map(AdminUserResponse::from);
  }

  @GetMapping("/{id}")
  @PreAuthorize("hasAuthority('USER_READ')")
  @Operation(summary = "Get a user")
  @ApiResponse(responseCode = "200", description = "User")
  @ApiResponse(responseCode = "404", description = "Unknown id")
  public AdminUserResponse get(@PathVariable Long id) {
    return AdminUserResponse.from(adminUserService.get(id));
  }

  @PutMapping("/{id}/disable")
  @PreAuthorize("hasAuthority('USER_WRITE')")
  @Operation(
      summary = "Disable a user",
      description = "Blocks authentication and revokes all of the user's sessions.")
  @ApiResponse(responseCode = "200", description = "User disabled")
  @ApiResponse(responseCode = "404", description = "Unknown id")
  @ApiResponse(responseCode = "409", description = "Admins cannot disable themselves")
  public AdminUserResponse disable(
      @Parameter(hidden = true) @AuthenticationPrincipal AuthUserDetails principal,
      @PathVariable Long id) {
    return AdminUserResponse.from(adminUserService.disable(principal.getUser().getId(), id));
  }

  @DeleteMapping("/{id}")
  @PreAuthorize("hasAuthority('USER_WRITE')")
  @Operation(
      summary = "Delete a user",
      description =
          "Hard delete of the user, roles, backup codes and sessions. Audit rows are kept.")
  @ApiResponse(responseCode = "204", description = "User deleted")
  @ApiResponse(responseCode = "404", description = "Unknown id")
  @ApiResponse(responseCode = "409", description = "Admins cannot delete themselves")
  public ResponseEntity<Void> delete(
      @Parameter(hidden = true) @AuthenticationPrincipal AuthUserDetails principal,
      @PathVariable Long id) {
    adminUserService.delete(principal.getUser().getId(), id);
    return ResponseEntity.noContent().build();
  }

  @PostMapping("/{id}/force-logout")
  @PreAuthorize("hasAuthority('USER_WRITE')")
  @Operation(
      summary = "Force logout",
      description = "Revokes every session of the user and returns how many were revoked.")
  @ApiResponse(responseCode = "200", description = "{\"sessionsRevoked\": n}")
  @ApiResponse(responseCode = "404", description = "Unknown id")
  public Map<String, Integer> forceLogout(
      @Parameter(hidden = true) @AuthenticationPrincipal AuthUserDetails principal,
      @PathVariable Long id) {
    return Map.of("sessionsRevoked", adminUserService.forceLogout(principal.getUser().getId(), id));
  }
}
