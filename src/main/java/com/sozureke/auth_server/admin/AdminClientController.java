package com.sozureke.auth_server.admin;

import com.sozureke.auth_server.admin.dto.AdminClientResponse;
import com.sozureke.auth_server.admin.dto.UpdateClientRequest;
import com.sozureke.auth_server.auth.AuthUserDetails;
import com.sozureke.auth_server.oauth.dto.OAuthClientResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
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
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin/clients")
@PreAuthorize("hasAuthority('CLIENT_MANAGE')")
@Tag(
    name = "Admin: OAuth clients",
    description =
        "Needs CLIENT_MANAGE. Clients are created with POST /api/clients. Secrets are never"
            + " returned except once on creation and rotation.")
public class AdminClientController {

  private final AdminClientService adminClientService;

  public AdminClientController(AdminClientService adminClientService) {
    this.adminClientService = adminClientService;
  }

  @GetMapping
  @Operation(
      summary = "List clients",
      description = "sort is limited to clientId, clientName, createdAt.")
  public Page<AdminClientResponse> list(
      @ParameterObject
          @PageableDefault(size = 20, sort = "clientId", direction = Sort.Direction.ASC)
          Pageable pageable) {
    return adminClientService.list(pageable).map(AdminClientResponse::from);
  }

  @GetMapping("/{clientId}")
  @Operation(summary = "Get a client")
  @ApiResponse(responseCode = "200", description = "Client")
  @ApiResponse(responseCode = "404", description = "Unknown client")
  public AdminClientResponse get(@PathVariable String clientId) {
    return AdminClientResponse.from(adminClientService.get(clientId));
  }

  @PutMapping("/{clientId}")
  @Operation(
      summary = "Update a client",
      description = "Replaces the name, redirect URIs and scopes.")
  @ApiResponse(responseCode = "200", description = "Client updated")
  @ApiResponse(responseCode = "400", description = "Validation failed")
  @ApiResponse(responseCode = "404", description = "Unknown client")
  public AdminClientResponse update(
      @Parameter(hidden = true) @AuthenticationPrincipal AuthUserDetails principal,
      @PathVariable String clientId,
      @Valid @RequestBody UpdateClientRequest request) {
    return AdminClientResponse.from(
        adminClientService.update(principal.getUser().getId(), clientId, request));
  }

  @DeleteMapping("/{clientId}")
  @Operation(summary = "Delete a client")
  @ApiResponse(responseCode = "204", description = "Client deleted")
  @ApiResponse(responseCode = "404", description = "Unknown client")
  public ResponseEntity<Void> delete(
      @Parameter(hidden = true) @AuthenticationPrincipal AuthUserDetails principal,
      @PathVariable String clientId) {
    adminClientService.delete(principal.getUser().getId(), clientId);
    return ResponseEntity.noContent().build();
  }

  @PostMapping("/{clientId}/rotate-secret")
  @Operation(
      summary = "Rotate the client secret",
      description = "Returns the new secret once. The old secret stops working immediately.")
  @ApiResponse(responseCode = "200", description = "New secret")
  @ApiResponse(responseCode = "404", description = "Unknown client")
  public OAuthClientResponse rotateSecret(
      @Parameter(hidden = true) @AuthenticationPrincipal AuthUserDetails principal,
      @PathVariable String clientId) {
    return new OAuthClientResponse(
        clientId, adminClientService.rotateSecret(principal.getUser().getId(), clientId));
  }
}
