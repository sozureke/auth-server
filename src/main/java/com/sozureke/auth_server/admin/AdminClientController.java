package com.sozureke.auth_server.admin;

import com.sozureke.auth_server.admin.dto.AdminClientResponse;
import com.sozureke.auth_server.admin.dto.UpdateClientRequest;
import com.sozureke.auth_server.auth.AuthUserDetails;
import com.sozureke.auth_server.oauth.dto.OAuthClientResponse;
import jakarta.validation.Valid;
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
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin/clients")
@PreAuthorize("hasAuthority('CLIENT_MANAGE')")
public class AdminClientController {

  private final AdminClientService adminClientService;

  public AdminClientController(AdminClientService adminClientService) {
    this.adminClientService = adminClientService;
  }

  @GetMapping
  public Page<AdminClientResponse> list(
      @PageableDefault(size = 20, sort = "clientId", direction = Sort.Direction.ASC)
          Pageable pageable) {
    return adminClientService.list(pageable).map(AdminClientResponse::from);
  }

  @GetMapping("/{clientId}")
  public AdminClientResponse get(@PathVariable String clientId) {
    return AdminClientResponse.from(adminClientService.get(clientId));
  }

  @PutMapping("/{clientId}")
  public AdminClientResponse update(
      @AuthenticationPrincipal AuthUserDetails principal,
      @PathVariable String clientId,
      @Valid @RequestBody UpdateClientRequest request) {
    return AdminClientResponse.from(
        adminClientService.update(principal.getUser().getId(), clientId, request));
  }

  @DeleteMapping("/{clientId}")
  public ResponseEntity<Void> delete(
      @AuthenticationPrincipal AuthUserDetails principal, @PathVariable String clientId) {
    adminClientService.delete(principal.getUser().getId(), clientId);
    return ResponseEntity.noContent().build();
  }

  @PostMapping("/{clientId}/rotate-secret")
  public OAuthClientResponse rotateSecret(
      @AuthenticationPrincipal AuthUserDetails principal, @PathVariable String clientId) {
    return new OAuthClientResponse(
        clientId, adminClientService.rotateSecret(principal.getUser().getId(), clientId));
  }
}
